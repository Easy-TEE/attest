use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::{to_string_pretty, to_value};

use attest::measure;
use attest::measure::uki::Uki;
use attest::types::PlatformMetadata;

#[derive(Parser)]
#[command(name = "attest")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Measure a confidential VM image
    #[command(subcommand)]
    Measure(Target),
}

#[derive(Subcommand)]
enum Target {
    /// Portable measurement: Azure PCRs + DCAP image hashes
    Portable {
        /// Image file to measure
        uki: PathBuf,
    },
    /// Native Azure vTPM PCR values
    Azure {
        /// Image file to measure
        uki: PathBuf,
        #[arg(long)]
        debug: bool,
    },
    /// Native GCP TDX register values
    Gcp {
        /// Image file to measure
        uki: PathBuf,
        /// Restrict to specific machine configs (default: all)
        #[arg(long = "config")]
        configs: Vec<String>,
        #[arg(long)]
        debug: bool,
    },
    /// Native self-hosted TDX register values (operator-controlled QEMU/TDVF)
    SelfHosted {
        /// Image file to measure
        uki: PathBuf,
        /// Firmware file
        #[arg(long)]
        firmware: PathBuf,
        #[arg(long, default_value_t = 1)]
        vcpus: u32,
        /// RAM size, e.g. "2G" or "512M"
        #[arg(long, default_value = "2G", value_parser = parse_ram)]
        ram: u64,
        #[arg(long)]
        debug: bool,
    },
}

fn main() -> Result<()> {
    let Cmd::Measure(target) = Cli::parse().command;
    let out = match target {
        Target::Portable { uki } => to_value(measure::measure(&std::fs::read(&uki)?)?)?,
        Target::Azure { uki, debug } => {
            let regs = measure::azure::measure(&load_uki(&uki)?);
            if debug {
                regs.debug_json()
            } else {
                to_value(&regs)?
            }
        }
        Target::Gcp {
            uki,
            configs,
            debug,
        } => {
            let hashes = measure::dcap::measure(&load_uki(&uki)?);
            let regs = measure::dcap::gcp::measure(&hashes, &configs)?;
            if debug {
                regs.debug_json()
            } else {
                to_value(&regs)?
            }
        }
        Target::SelfHosted {
            uki,
            firmware,
            vcpus,
            ram,
            debug,
        } => {
            let hashes = measure::dcap::measure(&load_uki(&uki)?);
            let fw = std::fs::read(&firmware)?;
            let platform = PlatformMetadata {
                vcpus,
                ram_bytes: ram,
                num_disks: 0,
            };
            let regs = measure::dcap::self_hosted::measure(&hashes, &fw, &platform)?;
            if debug {
                regs.debug_json()
            } else {
                to_value(&regs)?
            }
        }
    };
    println!("{}", to_string_pretty(&out)?);
    Ok(())
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
    num.parse::<u64>()
        .map(|n| n * mult)
        .map_err(|e| format!("invalid RAM size '{s}': {e}"))
}
