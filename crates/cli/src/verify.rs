use std::{
    io::{IsTerminal, Read},
    path::PathBuf,
};

use anyhow::{Result, bail};
use clap::Parser;
use pccs::Pccs;
use types::{AttestationEvidence, MeasurementOutput};

#[derive(Parser)]
pub(crate) struct Args {
    /// Path to expected measurement (JSON output of `attest measure ...`)
    #[arg(short, long)]
    measurement: PathBuf,

    /// Path to attestation evidence (output of `attest-prove` crate)
    /// If omitted, evidence is read from stdin
    evidence: Option<PathBuf>,

    /// PCCS URL (defaults to Intel PCS)
    #[arg(long)]
    pccs_url: Option<String>,

    /// Firmware blob (required for self-hosted Portable measurements)
    #[arg(long)]
    firmware: Option<PathBuf>,

    /// Print actual/expected register values on mismatch
    #[arg(short, long)]
    debug: bool,
}

pub(crate) fn run(args: Args) -> Result<()> {
    let expected: MeasurementOutput = serde_json::from_slice(&std::fs::read(&args.measurement)?)?;
    let evidence: AttestationEvidence = serde_json::from_slice(&read_evidence(args.evidence)?)?;
    let firmware = args.firmware.map(std::fs::read).transpose()?;

    let runtime = tokio::runtime::Runtime::new()?;
    let pccs = runtime.block_on(async {
        let pccs = Pccs::new(args.pccs_url);
        pccs.ready().await?;
        anyhow::Ok(pccs)
    })?;

    let report_data =
        verify::verify(&expected, &evidence, &pccs, firmware.as_deref(), args.debug)?;
    println!("{}", hex::encode(report_data));
    Ok(())
}

fn read_evidence(path: Option<PathBuf>) -> Result<Vec<u8>> {
    if let Some(path) = path {
        return Ok(std::fs::read(path)?);
    }
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        bail!("no evidence provided: pass a path or pipe via stdin");
    }
    let mut buf = Vec::new();
    stdin.read_to_end(&mut buf)?;
    Ok(buf)
}
