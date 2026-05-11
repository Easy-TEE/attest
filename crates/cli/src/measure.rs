use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Subcommand;
use measure::{Measurement, uki::Uki};
use serde_json::{Value, to_string_pretty, to_value};
use types::{MeasurementOutput, PortableMeasurements};

#[derive(Subcommand)]
pub(crate) enum Target {
    /// Cross-platform register values that aren't tied to firmware/platform
    Portable {
        /// Image file to measure
        uki: PathBuf,
        /// Omit the Azure PCR section (for non-Azure targets)
        #[arg(long)]
        no_azure: bool,
    },
    /// Azure vTPM PCR values
    Azure {
        /// Image file to measure
        uki: PathBuf,
        #[arg(long)]
        debug: bool,
    },
    /// Static GCP TDX register values
    Gcp {
        /// Image file to measure
        uki: PathBuf,
        /// Restrict to specific machine configs (default: all)
        #[arg(long = "config")]
        configs: Vec<String>,
        #[arg(long)]
        debug: bool,
    },
    /// Static self-hosted TDX register values
    SelfHosted {
        /// Image file to measure
        uki: PathBuf,
        /// Firmware file
        #[arg(long)]
        firmware: PathBuf,
        /// RAM size (e.g. "2G" or "512M")
        #[arg(long, default_value = "2G", value_parser = parse_ram)]
        ram: u64,
        #[arg(long)]
        debug: bool,
    },
}

pub(crate) fn run(target: Target) -> Result<()> {
    let out = match target {
        Target::Portable { uki, no_azure } => {
            let uki = load_uki(&uki)?;
            to_value(MeasurementOutput::Portable(PortableMeasurements {
                azure: (!no_azure).then(|| measure::azure::measure(&uki).finalize()),
                dcap: measure::dcap::measure(&uki),
            }))?
        }
        Target::Azure { uki, debug } => {
            emit(measure::azure::measure(&load_uki(&uki)?), debug, MeasurementOutput::Azure)?
        }
        Target::Gcp { uki, configs, debug } => {
            let hashes = measure::dcap::measure(&load_uki(&uki)?);
            emit(measure::dcap::gcp::measure(&hashes, &configs)?, debug, MeasurementOutput::Dcap)?
        }
        Target::SelfHosted { uki, firmware, ram, debug } => {
            let hashes = measure::dcap::measure(&load_uki(&uki)?);
            let fw = std::fs::read(&firmware)?;
            emit(
                measure::dcap::self_hosted::measure(&hashes, &fw, ram)?,
                debug,
                MeasurementOutput::Dcap,
            )?
        }
    };
    println!("{}", to_string_pretty(&out)?);
    Ok(())
}

fn emit<M: Measurement>(
    regs: M,
    debug: bool,
    wrap: impl FnOnce(M::Wire) -> MeasurementOutput,
) -> Result<Value> {
    Ok(if debug { regs.debug_json() } else { to_value(wrap(regs.finalize()))? })
}

fn load_uki(path: &Path) -> Result<Uki> {
    Uki::parse(&std::fs::read(path)?)
}

fn parse_ram(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('G') {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('M') {
        (n, 1024 * 1024)
    } else {
        (s, 1)
    };
    num.parse::<u64>().map(|n| n * mult).map_err(|e| format!("invalid RAM size '{s}': {e}"))
}
