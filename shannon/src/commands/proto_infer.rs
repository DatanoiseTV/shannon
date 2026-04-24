//! `shannon proto-infer` — infer a `.proto` from raw binary samples.

use std::fs::File;
use std::io::Write;

use anyhow::Result;

use crate::cli::{Cli, ProtoInferArgs};
use crate::proto_infer;

pub fn run(_cli: &Cli, args: ProtoInferArgs) -> Result<()> {
    let threads = if args.threads == 0 {
        std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(4)
    } else {
        args.threads
    };
    eprintln!(
        "shannon: inferring from {} using {threads} workers{}",
        args.samples.display(),
        args.time
            .map(|t| format!(" (budget {:?})", t))
            .unwrap_or_default()
    );
    let schema = proto_infer::infer_dir(&args.samples, threads, args.time, &args.message)?;
    let out = schema.to_proto();
    match args.output.as_deref() {
        Some(path) => {
            let mut f = File::create(path)?;
            f.write_all(out.as_bytes())?;
            eprintln!(
                "shannon: wrote {} bytes to {}  ({} fields, confidence {:.1}%)",
                out.len(),
                path.display(),
                schema.fields.len(),
                schema.confidence * 100.0
            );
        }
        None => {
            println!("{out}");
        }
    }
    Ok(())
}
