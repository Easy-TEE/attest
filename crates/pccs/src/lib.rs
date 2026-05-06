use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        RwLock,
        Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use dcap_qvl::{QuoteCollateralV3, collateral::get_collateral_for_fmspc, tcb_info::TcbInfo};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::{Duration, sleep},
};
use tracing::debug;
use x509_parser::{prelude::FromDer, revocation_list::CertificateRevocationList};

/// For fetching collateral directly from Intel
pub const PCS_URL: &str = "https://api.trustedservices.intel.com";
/// How long before expiry to refresh collateral
const REFRESH_MARGIN_SECS: i64 = 300;
/// How long to wait before retrying when failing to fetch collateral
const REFRESH_RETRY_SECS: u64 = 60;
/// How many collateral fetches to perform concurrently during initial
/// pre-warm
const STARTUP_PREWARM_CONCURRENCY: usize = 8;

/// PCCS collateral cache with proactive background refresh
#[derive(Clone)]
pub struct Pccs {
    /// The URL of the service used to fetch collateral (PCS / PCCS)
    url: String,
    /// The internal cache
    cache: Arc<RwLock<HashMap<PccsInput, CacheEntry>>>,
    /// Dedupes one-shot background refreshes for cache misses
    pending_refreshes: Arc<RwLock<HashSet<PccsInput>>>,
    /// The state of the initial pre-warm fetch
    prewarm_stats: Arc<PrewarmStats>,
    /// Completion signal for startup pre-warm, shared across all clones
    prewarm_outcome_tx: Option<watch::Sender<Option<PrewarmOutcome>>>,
}

impl std::fmt::Debug for Pccs {
    /// Formats PCCS config for debug output without exposing cache
    /// internals
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pccs").field("url", &self.url).finish_non_exhaustive()
    }
}

impl Pccs {
    /// Creates a new PCCS cache using the provided URL or Intel PCS default
    pub fn new(url: Option<String>) -> Self {
        let mut pccs = Self::new_without_prewarm(url);

        let (prewarm_outcome_tx, _) = watch::channel(None);
        pccs.prewarm_outcome_tx = Some(prewarm_outcome_tx);

        // Start filling the cache right away
        let pccs_for_prewarm = pccs.clone();
        tokio::spawn(async move {
            let outcome = pccs_for_prewarm.startup_prewarm_all_tdx().await;
            pccs_for_prewarm.finish_prewarm(outcome);
        });

        pccs
    }

    /// Creates a new PCCS cache using the provided URL or Intel PCS default
    /// and does not pre-warm by proactively fetching collateral
    pub fn new_without_prewarm(url: Option<String>) -> Self {
        let url = url
            .unwrap_or(PCS_URL.to_string())
            .trim_end_matches('/')
            .trim_end_matches("/sgx/certification/v4")
            .trim_end_matches("/tdx/certification/v4")
            .to_string();

        Self {
            url,
            cache: RwLock::new(HashMap::new()).into(),
            pending_refreshes: RwLock::new(HashSet::new()).into(),
            prewarm_stats: Arc::new(PrewarmStats::default()),
            prewarm_outcome_tx: None,
        }
    }

    /// Resolves when cache is pre-warmed with all available collateral
    pub async fn ready(&self) -> Result<PrewarmSummary, PccsError> {
        if let Some(prewarm_outcome_tx) = &self.prewarm_outcome_tx {
            let mut outcome_rx = prewarm_outcome_tx.subscribe();
            loop {
                if let Some(outcome) = outcome_rx.borrow_and_update().clone() {
                    return match outcome {
                        PrewarmOutcome::Ready(summary) => Ok(summary),
                        PrewarmOutcome::Failed(message) => Err(PccsError::PrewarmFailed(message)),
                    };
                }
                if outcome_rx.changed().await.is_err() {
                    return Err(PccsError::PrewarmSignalClosed);
                }
            }
        } else {
            Err(PccsError::PrewarmDisabled)
        }
    }

    /// Returns collateral from cache when valid, otherwise fetches and
    /// caches fresh collateral
    /// Returns collateral together with a flag indicating whether it is
    /// fresh (true) or from the cache (false)
    pub async fn get_collateral(
        &self,
        fmspc: String,
        ca: &'static str,
        now: u64,
    ) -> Result<(QuoteCollateralV3, bool), PccsError> {
        let now = i64::try_from(now).map_err(|_| PccsError::TimeStampExceedsI64)?;
        let cache_key = PccsInput::new(fmspc.clone(), ca);

        {
            let cache = self.cache.read().map_err(|_| PccsError::CachePoisoned)?;
            if let Some(entry) = cache.get(&cache_key) {
                if now < entry.next_update {
                    return Ok((entry.collateral.clone(), false));
                }
                tracing::warn!(
                    fmspc,
                    next_update = entry.next_update,
                    now,
                    "Cached collateral expired, refreshing from PCCS"
                );
            }
        }

        let collateral = fetch_collateral(&self.url, fmspc.clone(), ca).await?;
        let next_update = extract_next_update(&collateral, now)?;

        {
            let mut cache = self.cache.write().map_err(|_| PccsError::CachePoisoned)?;
            if let Some(existing) = cache.get(&cache_key) &&
                now < existing.next_update
            {
                return Ok((existing.collateral.clone(), false));
            }

            upsert_cache_entry(&mut cache, cache_key.clone(), collateral.clone(), next_update);
        }
        self.ensure_refresh_task(&cache_key).await;
        Ok((collateral, true))
    }

    /// A synchronous method to get collateral from the cache.
    ///
    /// If the requested collateral is not present in the cache, this will
    /// return an error rather than waiting to fetch it.  But it does
    /// begin fetching it in a background task.
    ///
    /// If the collateral is out of date, this will log a warning and return
    /// it anyway on a best-effort basis.
    pub fn get_collateral_sync(
        &self,
        fmspc: String,
        ca: &'static str,
        now: u64,
    ) -> Result<QuoteCollateralV3, PccsError> {
        let now = i64::try_from(now).map_err(|_| PccsError::TimeStampExceedsI64)?;
        let cache_key = PccsInput::new(fmspc.clone(), ca);
        let cache = self.cache.read().map_err(|_| PccsError::CachePoisoned)?;
        if let Some(entry) = cache.get(&cache_key) {
            if now >= entry.next_update {
                let collateral = entry.collateral.clone();
                tracing::warn!(
                    fmspc,
                    next_update = entry.next_update,
                    now,
                    "Cached collateral expired"
                );
                drop(cache);

                // Start a background task to renew
                let pccs = self.clone();
                tokio::spawn(async move {
                    pccs.ensure_refresh_task(&cache_key).await;
                });

                return Ok(collateral);
            }
            Ok(entry.collateral.clone())
        } else {
            drop(cache);
            self.spawn_background_refresh_for_cache_miss(cache_key.clone());
            Err(PccsError::NoCollateralForFmspc(format!("{cache_key:?}")))
        }
    }

    /// Fetches fresh collateral, overwrites cache, and ensures proactive
    /// refresh is scheduled
    async fn refresh_collateral(
        &self,
        fmspc: String,
        ca: &'static str,
    ) -> Result<QuoteCollateralV3, PccsError> {
        let now = unix_now()?;
        let collateral = fetch_collateral(&self.url, fmspc.clone(), ca).await?;
        let next_update = extract_next_update(&collateral, now)?;
        let cache_key = PccsInput::new(fmspc, ca);

        {
            let mut cache = self.cache.write().map_err(|_| PccsError::CachePoisoned)?;
            upsert_cache_entry(&mut cache, cache_key.clone(), collateral.clone(), next_update);
        }
        self.ensure_refresh_task(&cache_key).await;
        Ok(collateral)
    }

    /// Starts a background refresh loop for a cache key when no task is
    /// active
    #[allow(clippy::unused_async)]
    async fn ensure_refresh_task(&self, cache_key: &PccsInput) {
        let Ok(mut cache) = self.cache.write() else {
            tracing::warn!("PCCS cache lock poisoned, cannot ensure refresh task");
            return;
        };
        let Some(entry) = cache.get_mut(cache_key) else {
            return;
        };
        if entry.refresh_task.is_some() {
            return;
        }

        let weak_cache = Arc::downgrade(&self.cache);
        let key = cache_key.clone();
        let url = self.url.clone();
        entry.refresh_task = Some(tokio::spawn(async move {
            refresh_loop(weak_cache, url, key).await;
        }));
    }

    /// Starts a one-shot background fetch to populate a missing cache entry
    fn spawn_background_refresh_for_cache_miss(&self, cache_key: PccsInput) {
        {
            let Ok(mut pending_refreshes) = self.pending_refreshes.write() else {
                tracing::warn!("PCCS pending-refresh lock poisoned, cannot start sync refresh");
                return;
            };
            if !pending_refreshes.insert(cache_key.clone()) {
                return;
            }
        }

        let pccs = self.clone();
        tokio::spawn(async move {
            let result = pccs
                .refresh_collateral(
                    cache_key.fmspc.clone(),
                    ca_as_static(&cache_key.ca).expect("unsupported CA in pending refresh"),
                )
                .await;

            if let Err(err) = result {
                tracing::warn!(
                    fmspc = cache_key.fmspc,
                    ca = cache_key.ca,
                    error = %err,
                    "Sync-triggered PCCS cache repair failed"
                );
            }

            // Always clear the dedupe marker so a later sync miss can
            // retry if this repair attempt failed.
            if let Ok(mut pending_refreshes) = pccs.pending_refreshes.write() {
                pending_refreshes.remove(&cache_key);
            } else {
                tracing::warn!("PCCS pending-refresh lock poisoned during cleanup");
            }
        });
    }

    /// Pre-provisions TDX collateral for discovered FMSPC values to reduce
    /// hot-path fetches
    async fn startup_prewarm_all_tdx(&self) -> PrewarmOutcome {
        // First get all FMSPCs
        let fmspcs = match self.fetch_fmspcs().await {
            Ok(fmspcs) => fmspcs,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to fetch FMSPC list for startup pre-provision");
                return PrewarmOutcome::Failed(format!(
                    "Failed to fetch FMSPC list for prewarm: {e}"
                ));
            }
        };
        self.prewarm_stats.discovered_fmspcs.store(fmspcs.len(), Ordering::SeqCst);

        if fmspcs.is_empty() {
            tracing::warn!("No FMSPC entries returned during startup pre-provision");
            return PrewarmOutcome::Ready(self.prewarm_stats.snapshot());
        }

        // For each FMSPC, get the 'processor' and 'platform' collateral
        // concurrently
        let semaphore = Arc::new(Semaphore::new(STARTUP_PREWARM_CONCURRENCY));
        let mut join_set = JoinSet::new();
        for entry in fmspcs {
            for ca in ["processor", "platform"] {
                let permit = semaphore.clone().acquire_owned().await;
                let Ok(permit) = permit else {
                    continue;
                };
                self.prewarm_stats.attempted.fetch_add(1, Ordering::SeqCst);
                let pccs = self.clone();
                let fmspc = entry.fmspc.clone();
                join_set.spawn(async move {
                    let _permit = permit;
                    let result = pccs.refresh_collateral(fmspc.clone(), ca).await;
                    Ok::<(String, &'static str, Result<(), PccsError>), PccsError>((
                        fmspc,
                        ca,
                        result.map(|_| ()),
                    ))
                });
            }
        }

        // Collect results
        let mut successes = 0usize;
        let mut failures = 0usize;
        while let Some(task_result) = join_set.join_next().await {
            match task_result {
                Ok(Ok((fmspc, ca, Ok(())))) => {
                    successes += 1;
                    debug!("Successfully cached: {fmspc} {ca}");
                    self.prewarm_stats.successes.fetch_add(1, Ordering::SeqCst);
                }
                Ok(Ok((fmspc, ca, Err(e)))) => {
                    failures += 1;
                    self.prewarm_stats.failures.fetch_add(1, Ordering::SeqCst);
                    tracing::debug!(
                        fmspc,
                        ca,
                        error = %e,
                        "Startup pre-provision: FMSPC/CA not cached:"
                    );
                }
                Ok(Err(e)) => {
                    failures += 1;
                    self.prewarm_stats.failures.fetch_add(1, Ordering::SeqCst);
                    tracing::debug!(error = %e, "Startup pre-provision task failed");
                }
                Err(e) => {
                    failures += 1;
                    self.prewarm_stats.failures.fetch_add(1, Ordering::SeqCst);
                    tracing::debug!(error = %e, "Startup pre-provision join error");
                }
            }
        }
        tracing::info!(
            discovered_fmspcs = self.prewarm_stats.discovered_fmspcs.load(Ordering::SeqCst),
            attempted = self.prewarm_stats.attempted.load(Ordering::SeqCst),
            successes,
            failures,
            "Completed PCCS startup pre-provisioning for TDX collateral"
        );
        PrewarmOutcome::Ready(self.prewarm_stats.snapshot())
    }

    fn finish_prewarm(&self, outcome: PrewarmOutcome) {
        if let Some(prewarm_outcome_tx) = &self.prewarm_outcome_tx {
            self.prewarm_stats.completed.store(true, Ordering::SeqCst);
            let _ = prewarm_outcome_tx.send(Some(outcome));
        }
    }

    /// Fetches available FMSPC entries from configured PCCS/PCS endpoint
    async fn fetch_fmspcs(&self) -> Result<Vec<FmspcEntry>, PccsError> {
        let url = format!("{}/sgx/certification/v4/fmspcs", self.url);
        let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(PccsError::FmspcFetch(response.status()));
        }
        let body = response.text().await?;
        let entries: Vec<FmspcEntry> = serde_json::from_str(&body)?;
        Ok(entries)
    }
}

/// Final startup pre-warm status and counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrewarmSummary {
    pub discovered_fmspcs: usize,
    pub attempted: usize,
    pub successes: usize,
    pub failures: usize,
}

#[derive(Clone, Debug)]
enum PrewarmOutcome {
    Ready(PrewarmSummary),
    Failed(String),
}

/// Cache key for PCCS collateral entries
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct PccsInput {
    fmspc: String,
    ca: String,
}

impl PccsInput {
    /// Builds a cache key from FMSPC and CA identifier
    fn new(fmspc: String, ca: &'static str) -> Self {
        Self { fmspc, ca: ca.to_string() }
    }
}

/// Fetches collateral from PCCS for a given FMSPC and CA
async fn fetch_collateral(
    url: &str,
    fmspc: String,
    ca: &'static str,
) -> Result<QuoteCollateralV3, PccsError> {
    get_collateral_for_fmspc(
        url, fmspc, ca, false, // Indicates not SGX
    )
    .await
    .map_err(Into::into)
}

/// Extracts the earliest next update timestamp from collateral metadata
///
/// This returns the soonest timestamp from either:
/// - The TCB
/// - The Quoting enclave
/// - The root CA certificate revocation list
/// - The PCK certificate revocation list
fn extract_next_update(collateral: &QuoteCollateralV3, now: i64) -> Result<i64, PccsError> {
    let tcb_info: TcbInfo = serde_json::from_str(&collateral.tcb_info).map_err(|e| {
        PccsError::PccsCollateralParse(format!("Failed to parse TCB info JSON: {e}"))
    })?;
    let qe_identity: QeIdentityNextUpdate =
        serde_json::from_str(&collateral.qe_identity).map_err(|e| {
            PccsError::PccsCollateralParse(format!("Failed to parse QE identity JSON: {e}"))
        })?;

    let tcb_next_update = parse_next_update("tcb_info.nextUpdate", &tcb_info.next_update)?;
    let qe_next_update = parse_next_update("qe_identity.nextUpdate", &qe_identity.next_update)?;
    let root_ca_crl_next_update =
        parse_crl_next_update("root_ca_crl.nextUpdate", &collateral.root_ca_crl)?;
    let pck_crl_next_update = parse_crl_next_update("pck_crl.nextUpdate", &collateral.pck_crl)?;
    let next_update =
        tcb_next_update.min(qe_next_update).min(root_ca_crl_next_update).min(pck_crl_next_update);

    if now >= next_update {
        return Err(PccsError::PccsCollateralExpired(format!(
            "Collateral expired (tcb_next_update={}, qe_next_update={}, root_ca_crl_next_update={}, pck_crl_next_update={}, now={now})",
            tcb_info.next_update,
            qe_identity.next_update,
            root_ca_crl_next_update,
            pck_crl_next_update
        )));
    }

    Ok(next_update)
}

/// Parses an RFC3339 nextUpdate value into a unix timestamp
fn parse_next_update(field: &str, value: &str) -> Result<i64, PccsError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|e| {
            PccsError::PccsCollateralParse(format!("Failed to parse {field} as RFC3339: {e}"))
        })
        .map(|parsed| parsed.unix_timestamp())
}

/// Parse a certifcate revocation list and extract the timestamp for next
/// update
fn parse_crl_next_update(field: &str, crl_der: &[u8]) -> Result<i64, PccsError> {
    let (_, crl) = CertificateRevocationList::from_der(crl_der).map_err(|e| {
        PccsError::PccsCollateralParse(format!("Failed to parse {field} as DER CRL: {e}"))
    })?;
    let next_update = crl
        .next_update()
        .ok_or_else(|| PccsError::PccsCollateralParse(format!("Missing {field} in DER CRL")))?;
    Ok(next_update.timestamp())
}

/// Returns current unix time in seconds
fn unix_now() -> Result<i64, PccsError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64)
}

/// Computes how many seconds to sleep before refresh should start
fn refresh_sleep_seconds(next_update: i64, now: i64) -> u64 {
    let refresh_at = next_update - REFRESH_MARGIN_SECS;
    if refresh_at <= now { 0 } else { (refresh_at - now) as u64 }
}

/// Inserts or updates a cache entry while preserving any active refresh
/// task
fn upsert_cache_entry(
    cache: &mut HashMap<PccsInput, CacheEntry>,
    key: PccsInput,
    collateral: QuoteCollateralV3,
    next_update: i64,
) {
    match cache.get_mut(&key) {
        Some(existing) => {
            existing.collateral = collateral;
            existing.next_update = next_update;
        }
        None => {
            cache.insert(key, CacheEntry { collateral, next_update, refresh_task: None });
        }
    }
}

/// Converts CA identifier string into the expected static literal
fn ca_as_static(ca: &str) -> Option<&'static str> {
    match ca {
        "processor" => Some("processor"),
        "platform" => Some("platform"),
        _ => None,
    }
}

/// Background loop that refreshes collateral for a single cache key
async fn refresh_loop(
    weak_cache: Weak<RwLock<HashMap<PccsInput, CacheEntry>>>,
    pccs_url: String,
    key: PccsInput,
) {
    let Some(ca_static) = ca_as_static(&key.ca) else {
        tracing::warn!(ca = key.ca, "Unsupported collateral CA value, refresh loop stopping");
        return;
    };

    loop {
        let Some(cache) = weak_cache.upgrade() else {
            return;
        };
        let next_update = {
            let Ok(cache_guard) = cache.read() else {
                tracing::warn!("PCCS cache lock poisoned, refresh loop stopping");
                return;
            };
            let Some(entry) = cache_guard.get(&key) else {
                return;
            };
            entry.next_update
        };

        // Sleep until shortly before next update is due
        let now = match unix_now() {
            Ok(now) => now,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to read system time for PCCS refresh");
                sleep(Duration::from_secs(REFRESH_RETRY_SECS)).await;
                continue;
            }
        };
        let sleep_secs = refresh_sleep_seconds(next_update, now);
        sleep(Duration::from_secs(sleep_secs)).await;

        // Re-check the entry after waking in case another task updated it
        let now = match unix_now() {
            Ok(now) => now,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to read system time for PCCS refresh");
                sleep(Duration::from_secs(REFRESH_RETRY_SECS)).await;
                continue;
            }
        };
        let Some(cache) = weak_cache.upgrade() else {
            return;
        };
        let should_refresh = {
            let Ok(cache_guard) = cache.read() else {
                tracing::warn!("PCCS cache lock poisoned, refresh loop stopping");
                return;
            };
            let Some(entry) = cache_guard.get(&key) else {
                return;
            };
            refresh_sleep_seconds(entry.next_update, now) == 0
        };
        if !should_refresh {
            // The cached schedule moved forward, so skip the redundant fetch.
            continue;
        }

        match fetch_collateral(&pccs_url, key.fmspc.clone(), ca_static).await {
            Ok(collateral) => {
                let validate_now = match unix_now() {
                    Ok(timestamp) => timestamp,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Failed to read system time for PCCS refresh validation"
                        );
                        sleep(Duration::from_secs(REFRESH_RETRY_SECS)).await;
                        continue;
                    }
                };
                match extract_next_update(&collateral, validate_now) {
                    Ok(new_next_update) => {
                        let Some(cache) = weak_cache.upgrade() else {
                            return;
                        };
                        let Ok(mut cache_guard) = cache.write() else {
                            tracing::warn!("PCCS cache lock poisoned, refresh loop stopping");
                            return;
                        };
                        let Some(entry) = cache_guard.get_mut(&key) else {
                            return;
                        };
                        entry.collateral = collateral;
                        entry.next_update = new_next_update;
                        tracing::debug!(
                            fmspc = key.fmspc,
                            ca = key.ca,
                            next_update = new_next_update,
                            "Refreshed PCCS collateral in background"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            fmspc = key.fmspc,
                            ca = key.ca,
                            error = %e,
                            "Fetched PCCS collateral but nextUpdate validation failed"
                        );
                        sleep(Duration::from_secs(REFRESH_RETRY_SECS)).await;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    fmspc = key.fmspc,
                    ca = key.ca,
                    error = %e,
                    "Background PCCS collateral refresh failed"
                );
                sleep(Duration::from_secs(REFRESH_RETRY_SECS)).await;
            }
        }
    }
}

/// Cached collateral entry with refresh metadata
struct CacheEntry {
    collateral: QuoteCollateralV3,
    next_update: i64,
    refresh_task: Option<JoinHandle<()>>,
}

/// Minimal QE identity shape needed to read nextUpdate
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct QeIdentityNextUpdate {
    next_update: String,
}

#[derive(Debug, serde::Deserialize)]
struct FmspcEntry {
    fmspc: String,
    #[allow(dead_code)]
    platform: String,
}

#[derive(Default)]
struct PrewarmStats {
    discovered_fmspcs: AtomicUsize,
    attempted: AtomicUsize,
    successes: AtomicUsize,
    failures: AtomicUsize,
    completed: AtomicBool,
}

impl PrewarmStats {
    fn snapshot(&self) -> PrewarmSummary {
        PrewarmSummary {
            discovered_fmspcs: self.discovered_fmspcs.load(Ordering::SeqCst),
            attempted: self.attempted.load(Ordering::SeqCst),
            successes: self.successes.load(Ordering::SeqCst),
            failures: self.failures.load(Ordering::SeqCst),
        }
    }
}

#[derive(Error, Debug)]
pub enum PccsError {
    #[error("DCAP quote verification: {0}")]
    DcapQvl(#[from] anyhow::Error),
    #[error("PCCS collateral parse error: {0}")]
    PccsCollateralParse(String),
    #[error("PCCS collateral expired: {0}")]
    PccsCollateralExpired(String),
    #[error("System Time: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("HTTP client: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed to fetch FMSPC: {0}")]
    FmspcFetch(reqwest::StatusCode),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("PCCS prewarm failed: {0}")]
    PrewarmFailed(String),
    #[error("PCCS prewarm signal channel closed before completion")]
    PrewarmSignalClosed,
    #[error("PCCS prewarm is disabled for this instance")]
    PrewarmDisabled,
    #[error("Timestamp exceeds i64 range")]
    TimeStampExceedsI64,
    #[error("PCCS cache lock poisoned")]
    CachePoisoned,
    #[error("No collateral in cache for FMSPC {0}")]
    NoCollateralForFmspc(String),
}

#[cfg(test)]
mod mock_pcs;

#[cfg(test)]
mod tests;
