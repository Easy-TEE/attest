mod dump;
mod measure;
#[cfg(feature = "prove")]
mod prove;
#[cfg(feature = "verify")]
mod verify;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    Measure(measure::Target),
    /// Generate an attestation for the current CVM
    #[cfg(feature = "prove")]
    Prove(prove::Args),
    /// Verify an attestation against an expected measurement
    #[cfg(feature = "verify")]
    Verify(verify::Args),
    /// Dump the current CVM's event log and register values
    Dump(dump::Args),
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Cmd::Measure(target) => measure::run(target),
        #[cfg(feature = "prove")]
        Cmd::Prove(args) => prove::run(args),
        #[cfg(feature = "verify")]
        Cmd::Verify(args) => verify::run(args),
        Cmd::Dump(args) => dump::run(args),
    }
}
