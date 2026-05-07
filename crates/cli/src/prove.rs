use std::{
    io::{IsTerminal, Read},
    path::PathBuf,
};

use anyhow::{Result, anyhow, bail};
use clap::Parser;
use serde_json::to_string_pretty;

#[derive(Parser)]
pub(crate) struct Args {
    /// 64-byte report-data, hex-encoded (128 hex chars).
    /// If omitted, raw 64 bytes are read from --file or stdin
    input_data: Option<String>,

    /// Read raw 64-byte report-data from a file
    #[arg(short, long, conflicts_with = "input_data")]
    file: Option<PathBuf>,
}

pub(crate) fn run(args: Args) -> Result<()> {
    let input_data = read_input_data(args)?;
    let evidence = prove::prove(input_data)?;
    println!("{}", to_string_pretty(&evidence)?);
    Ok(())
}

fn read_input_data(args: Args) -> Result<[u8; 64]> {
    let bytes = match (args.input_data, args.file) {
        (Some(hex), None) => hex::decode(hex.trim())?,
        (None, Some(path)) => std::fs::read(path)?,
        (None, None) => {
            let mut stdin = std::io::stdin();
            if stdin.is_terminal() {
                bail!("no input data: pass hex as a positional arg, --file, or pipe via stdin");
            }
            let mut buf = Vec::with_capacity(64);
            stdin.read_to_end(&mut buf)?;
            buf
        }
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts_with"),
    };
    bytes.try_into().map_err(|v: Vec<u8>| anyhow!("expected 64 bytes, got {}", v.len()))
}
