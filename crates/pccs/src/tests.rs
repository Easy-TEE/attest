use tokio::time::Duration;

use super::{
    mock_pcs::{MockPcsConfig, spawn_mock_pcs_server},
    *,
};

#[tokio::test]
async fn test_mock_pcs_server_helper_with_get_collateral() {
    let mock = spawn_mock_pcs_server(MockPcsConfig {
        fmspc: "00806F050000".to_string(),
        include_fmspcs_listing: false,
        tcb_next_update: "2999-01-01T00:00:00Z".to_string(),
        qe_next_update: "2999-01-01T00:00:00Z".to_string(),
        refreshed_tcb_next_update: None,
        refreshed_qe_next_update: None,
    })
    .await;

    let pccs = Pccs::new(Some(mock.base_url.clone()));
    let now = 1_700_000_000_u64;
    let (_, is_fresh) =
        pccs.get_collateral("00806F050000".to_string(), "processor", now).await.unwrap();
    assert!(is_fresh);
}

#[test]
fn test_extract_next_update_includes_crl_expiry() {
    let mut collateral: QuoteCollateralV3 =
        serde_saphyr::from_slice(include_bytes!("test-assets/dcap-quote-collateral-00.yaml"))
            .unwrap();

    let mut tcb_info: serde_json::Value = serde_json::from_str(&collateral.tcb_info).unwrap();
    tcb_info["nextUpdate"] = serde_json::Value::String("2999-01-01T00:00:00Z".to_string());
    collateral.tcb_info = serde_json::to_string(&tcb_info).unwrap();

    let mut qe_identity: serde_json::Value = serde_json::from_str(&collateral.qe_identity).unwrap();
    qe_identity["nextUpdate"] = serde_json::Value::String("2999-01-01T00:00:00Z".to_string());
    collateral.qe_identity = serde_json::to_string(&qe_identity).unwrap();

    let expected = parse_crl_next_update("root_ca_crl.nextUpdate", &collateral.root_ca_crl)
        .unwrap()
        .min(parse_crl_next_update("pck_crl.nextUpdate", &collateral.pck_crl).unwrap());

    assert_eq!(extract_next_update(&collateral, 0).unwrap(), expected);
}

#[tokio::test]
async fn test_proactive_refresh_updates_cached_entry() {
    let initial_now = unix_now().unwrap();
    let initial_next_update =
        OffsetDateTime::from_unix_timestamp(initial_now + 2).unwrap().format(&Rfc3339).unwrap();
    let refreshed_next_update =
        OffsetDateTime::from_unix_timestamp(initial_now + 3600).unwrap().format(&Rfc3339).unwrap();

    let mock = spawn_mock_pcs_server(MockPcsConfig {
        fmspc: "00806F050000".to_string(),
        include_fmspcs_listing: false,
        tcb_next_update: initial_next_update.clone(),
        qe_next_update: initial_next_update,
        refreshed_tcb_next_update: Some(refreshed_next_update.clone()),
        refreshed_qe_next_update: Some(refreshed_next_update),
    })
    .await;

    let pccs = Pccs::new(Some(mock.base_url.clone()));
    let (_, is_fresh) = pccs
        .get_collateral("00806F050000".to_string(), "processor", initial_now as u64)
        .await
        .unwrap();
    assert!(is_fresh);
    assert_eq!(mock.tcb_call_count(), 1);
    assert_eq!(mock.qe_call_count(), 1);

    let (_, is_fresh_second) = pccs
        .get_collateral("00806F050000".to_string(), "processor", initial_now as u64)
        .await
        .unwrap();
    assert!(!is_fresh_second);
    assert_eq!(mock.tcb_call_count(), 1);
    assert_eq!(mock.qe_call_count(), 1);

    for _ in 0..60 {
        if mock.tcb_call_count() >= 2 && mock.qe_call_count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(mock.tcb_call_count() >= 2, "expected proactive TCB refresh to run");
    assert!(mock.qe_call_count() >= 2, "expected proactive QE identity refresh to run");

    let before_check_calls = mock.tcb_call_count();
    let now_after_background = unix_now().unwrap();
    let (_, is_fresh_again) = pccs
        .get_collateral("00806F050000".to_string(), "processor", now_after_background as u64)
        .await
        .unwrap();
    assert!(!is_fresh_again);
    assert_eq!(mock.tcb_call_count(), before_check_calls);
}

#[tokio::test]
async fn test_ready_waits_for_startup_prewarm() {
    let mock = spawn_mock_pcs_server(MockPcsConfig {
        fmspc: "00806F050000".to_string(),
        include_fmspcs_listing: true,
        tcb_next_update: "2999-01-01T00:00:00Z".to_string(),
        qe_next_update: "2999-01-01T00:00:00Z".to_string(),
        refreshed_tcb_next_update: None,
        refreshed_qe_next_update: None,
    })
    .await;
    let pccs = Pccs::new(Some(mock.base_url.clone()));
    let summary =
        tokio::time::timeout(Duration::from_secs(5), pccs.ready()).await.unwrap().unwrap();
    assert_eq!(summary.discovered_fmspcs, 1);
    assert_eq!(summary.attempted, 2);
    assert_eq!(summary.successes, 2);
    assert_eq!(summary.failures, 0);

    let (total_entries, fmspc, ca) = {
        let cache_guard = pccs.cache.read().unwrap();
        let total_entries = cache_guard.len();
        let (fmspc, ca) = cache_guard
            .keys()
            .next()
            .map(|k| (k.fmspc.clone(), k.ca.clone()))
            .expect("expected startup pre-provision to populate PCCS cache");
        (total_entries, fmspc, ca)
    };
    assert_eq!(total_entries, 2, "expected startup pre-provision to cache processor+platform");
    let ca_static = ca_as_static(&ca).expect("unexpected CA value in warmed cache entry");
    let now = unix_now().unwrap();
    let (_, is_fresh) = pccs.get_collateral(fmspc, ca_static, now as u64).await.unwrap();
    assert!(!is_fresh);
}

#[tokio::test]
async fn test_ready_supports_multiple_waiters() {
    let mock = spawn_mock_pcs_server(MockPcsConfig {
        fmspc: "00806F050000".to_string(),
        include_fmspcs_listing: true,
        tcb_next_update: "2999-01-01T00:00:00Z".to_string(),
        qe_next_update: "2999-01-01T00:00:00Z".to_string(),
        refreshed_tcb_next_update: None,
        refreshed_qe_next_update: None,
    })
    .await;
    let pccs = Pccs::new(Some(mock.base_url.clone()));
    let pccs_clone = pccs.clone();

    let (first, second) = tokio::join!(pccs.ready(), pccs_clone.ready());
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first, second);
    assert_eq!(first.discovered_fmspcs, 1);
}

#[tokio::test]
async fn test_ready_returns_error_when_prewarm_bootstrap_fails() {
    let pccs = Pccs::new(Some("http://127.0.0.1:1".to_string()));
    let ready_result = tokio::time::timeout(Duration::from_secs(2), pccs.ready()).await.unwrap();
    assert!(matches!(ready_result, Err(PccsError::PrewarmFailed(_))));
}

#[tokio::test]
async fn test_ready_returns_error_when_prewarm_disabled() {
    let pccs = Pccs::new_without_prewarm(None);
    let ready_result = pccs.ready().await;
    assert!(matches!(ready_result, Err(PccsError::PrewarmDisabled)));
}

#[tokio::test]
async fn test_get_collateral_sync_repairs_cache_miss_in_background() {
    let mock = spawn_mock_pcs_server(MockPcsConfig {
        fmspc: "00806F050000".to_string(),
        include_fmspcs_listing: false,
        tcb_next_update: "2999-01-01T00:00:00Z".to_string(),
        qe_next_update: "2999-01-01T00:00:00Z".to_string(),
        refreshed_tcb_next_update: None,
        refreshed_qe_next_update: None,
    })
    .await;

    let pccs = Pccs::new_without_prewarm(Some(mock.base_url.clone()));
    let now = unix_now().unwrap() as u64;

    let err = pccs.get_collateral_sync("00806F050000".to_string(), "processor", now);
    assert!(matches!(err, Err(PccsError::NoCollateralForFmspc(_))));

    for _ in 0..50 {
        if pccs.get_collateral_sync("00806F050000".to_string(), "processor", now).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let collateral = pccs.get_collateral_sync("00806F050000".to_string(), "processor", now);
    assert!(collateral.is_ok(), "expected sync miss repair to populate cache");
    assert_eq!(mock.tcb_call_count(), 1);
    assert_eq!(mock.qe_call_count(), 1);
}

#[tokio::test]
async fn test_get_collateral_sync_repairs_expired_cache_entry_in_background() {
    let initial_now = unix_now().unwrap();
    let initial_next_update =
        OffsetDateTime::from_unix_timestamp(initial_now + 1).unwrap().format(&Rfc3339).unwrap();
    let refreshed_next_update =
        OffsetDateTime::from_unix_timestamp(initial_now + 3600).unwrap().format(&Rfc3339).unwrap();

    let mock = spawn_mock_pcs_server(MockPcsConfig {
        fmspc: "00806F050000".to_string(),
        include_fmspcs_listing: false,
        tcb_next_update: initial_next_update.clone(),
        qe_next_update: initial_next_update,
        refreshed_tcb_next_update: Some(refreshed_next_update.clone()),
        refreshed_qe_next_update: Some(refreshed_next_update),
    })
    .await;

    let pccs = Pccs::new_without_prewarm(Some(mock.base_url.clone()));
    let (_, is_fresh) = pccs
        .get_collateral("00806F050000".to_string(), "processor", initial_now as u64)
        .await
        .unwrap();
    assert!(is_fresh);

    {
        let mut cache = pccs.cache.write().unwrap();
        let entry = cache
            .get_mut(&PccsInput::new("00806F050000".to_string(), "processor"))
            .expect("expected cached collateral entry");
        entry.next_update = initial_now - 1;
        entry.refresh_task = None;
    }

    let stale_collateral =
        pccs.get_collateral_sync("00806F050000".to_string(), "processor", initial_now as u64);
    assert!(stale_collateral.is_ok(), "expected stale collateral to be returned");

    for _ in 0..50 {
        if mock.tcb_call_count() >= 2 && mock.qe_call_count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(mock.tcb_call_count() >= 2, "expected background refresh after sync expired hit");
    assert!(mock.qe_call_count() >= 2, "expected background refresh after sync expired hit");
}
