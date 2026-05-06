//! Demonstrates setting up a PCCS cache using Intel PCS
use std::time::Instant;

use attest_pccs::{PCS_URL, Pccs};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

fn init_logging() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,pccs=debug"));

    fmt().with_env_filter(env_filter).with_target(false).compact().init();
}

#[tokio::main]
async fn main() -> Result<(), attest_pccs::PccsError> {
    init_logging();

    info!(pcs_url = PCS_URL, "Starting PCCS with Intel PCS");

    let pccs = Pccs::new(None);
    let started_at = Instant::now();
    let summary = pccs.ready().await?;
    let elapsed = started_at.elapsed().as_secs_f64();

    println!("Intel PCS startup prewarm complete");
    println!("Elapsed seconds: {elapsed:.2}");
    println!("Discovered FMSPC entries: {}", summary.discovered_fmspcs);
    println!("Collateral fetch attempts: {}", summary.attempted);
    println!("Collateral fetch successes: {}", summary.successes);
    println!("Collateral fetch failures: {}", summary.failures);

    Ok(())
}
