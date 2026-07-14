use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Subcommand;
use measure::{Measurement, get_rootfs_header, uki::Uki};
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
        /// Optional rootfs disk image (defaults to `<uki>.raw` if present)
        #[arg(long)]
        raw: Option<PathBuf>,
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
        #[arg(long)]
        debug: bool,
        /// Optional rootfs disk image (defaults to `<uki>.raw` if present)
        #[arg(long)]
        raw: Option<PathBuf>,
    },
    /// Static self-hosted TDX register values
    SelfHosted {
        /// Image file to measure
        uki: PathBuf,
        #[arg(long)]
        debug: bool,
        /// Optional rootfs disk image (defaults to `<uki>.raw` if present)
        #[arg(long)]
        raw: Option<PathBuf>,
    },
}

pub(crate) fn run(target: Target) -> Result<()> {
    let out = match target {
        Target::Portable { uki, no_azure, raw } => {
            let gpt = load_gpt(&uki, raw.as_deref())?;
            let uki = load_uki(&uki)?;
            to_value(MeasurementOutput::Portable(Box::new(PortableMeasurements {
                azure: (!no_azure).then(|| measure::azure::measure(&uki).finalize()),
                dcap: measure::dcap::measure(&uki, gpt.as_deref()),
            })))?
        }
        Target::Azure { uki, debug } => {
            emit(measure::azure::measure(&load_uki(&uki)?), debug, MeasurementOutput::Azure)?
        }
        Target::Gcp { uki, debug, raw } => {
            let gpt = load_gpt(&uki, raw.as_deref())?;
            let hashes = measure::dcap::measure(&load_uki(&uki)?, gpt.as_deref());
            emit(measure::dcap::gcp::measure(&hashes), debug, MeasurementOutput::Dcap)?
        }
        Target::SelfHosted { uki, debug, raw } => {
            let gpt = load_gpt(&uki, raw.as_deref())?;
            let hashes = measure::dcap::measure(&load_uki(&uki)?, gpt.as_deref());
            emit(measure::dcap::self_hosted::measure(&hashes), debug, MeasurementOutput::Dcap)?
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
    Ok(Uki::parse(&std::fs::read(path)?)?)
}

fn load_gpt(uki: &Path, raw: Option<&Path>) -> Result<Option<Vec<u8>>> {
    let sibling_file = uki.with_extension("raw");
    let path = match raw {
        Some(p) => p,
        None if sibling_file.exists() => sibling_file.as_path(),
        _ => return Ok(None),
    };
    Ok(Some(get_rootfs_header(path)?.to_vec()))
}
