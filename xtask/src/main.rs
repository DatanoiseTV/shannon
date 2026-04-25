//! Build orchestrator for the shannon project.
//!
//! Cargo alone can't cleanly build this workspace because the `shannon-ebpf`
//! crate needs a different target (`bpfel-unknown-none`), a different toolchain
//! (nightly), and a `build-std` invocation. `xtask` exists to hide that from
//! developers: `cargo xtask build` does the right thing.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "xtask", about = "shannon build orchestrator", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build userspace + eBPF (default: debug profile).
    Build(BuildArgs),
    /// Run `cargo test` across the workspace (skips the eBPF crate, which is
    /// not testable on the host target).
    Test(TestArgs),
    /// Run clippy on both workspaces.
    Lint,
    /// Format everything.
    Fmt {
        /// Just check, don't write.
        #[arg(long)]
        check: bool,
    },
    /// Build and then launch shannon. Requires capabilities / root.
    Run(RunArgs),
    /// Remove build artefacts.
    Clean,
    /// Build shannon (release), then emit manpages into `target/manpages/`.
    Manpages,
}

#[derive(clap::Args)]
struct BuildArgs {
    /// Build the release profile (optimised, stripped).
    #[arg(long)]
    release: bool,
    /// Only build the eBPF crate.
    #[arg(long, conflicts_with = "userspace_only")]
    ebpf_only: bool,
    /// Only build the userspace crate.
    #[arg(long = "userspace-only", conflicts_with = "ebpf_only")]
    userspace_only: bool,
}

#[derive(clap::Args)]
struct TestArgs {
    /// Pass-through arguments to `cargo test`.
    #[arg(last = true)]
    rest: Vec<String>,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Release profile.
    #[arg(long)]
    release: bool,
    /// Arguments forwarded to the shannon binary.
    #[arg(last = true)]
    rest: Vec<String>,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
#[allow(dead_code)]
enum Profile {
    Debug,
    Release,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build(args) => cmd_build(&args),
        Cmd::Test(args) => cmd_test(&args),
        Cmd::Lint => cmd_lint(),
        Cmd::Fmt { check } => cmd_fmt(check),
        Cmd::Run(args) => cmd_run(&args),
        Cmd::Clean => cmd_clean(),
        Cmd::Manpages => cmd_manpages(),
    }
}

fn cmd_manpages() -> Result<()> {
    let root = workspace_root()?;
    // Build a release shannon so the binary that knows the current CLI
    // shape produces the manpages. Cheaper than re-implementing the
    // walk in xtask.
    let status = Command::new(cargo_cmd())
        .current_dir(&root)
        .args(["build", "--release", "-p", "shannon"])
        .status()
        .context("cargo build -p shannon")?;
    check_status("cargo build", status)?;

    let bin = root.join("target/release/shannon");
    let out = root.join("target/manpages");
    let status = Command::new(&bin)
        .arg("manpages")
        .arg(&out)
        .status()
        .with_context(|| format!("running {}", bin.display()))?;
    check_status("shannon manpages", status)?;
    println!("manpages written to {}", out.display());
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let out = Command::new(cargo_cmd())
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .context("running `cargo locate-project`")?;
    if !out.status.success() {
        bail!(
            "cargo locate-project failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let toml = String::from_utf8(out.stdout).context("non-utf8 cargo output")?;
    let root = Path::new(toml.trim())
        .parent()
        .context("workspace manifest has no parent")?
        .to_path_buf();
    Ok(root)
}

fn cargo_cmd() -> String {
    env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn check_status(cmd_name: &str, status: ExitStatus) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        bail!("{cmd_name} exited with {status}");
    }
}

fn cmd_build(args: &BuildArgs) -> Result<()> {
    let root = workspace_root()?;
    if !args.userspace_only {
        build_ebpf(&root, args.release)?;
    }
    if !args.ebpf_only {
        build_userspace(&root, args.release)?;
    }
    Ok(())
}

fn build_ebpf(root: &Path, release: bool) -> Result<()> {
    let manifest = root.join("shannon-ebpf").join("Cargo.toml");
    let mut cmd = Command::new(cargo_cmd());
    cmd.current_dir(root.join("shannon-ebpf"))
        .args([
            "+nightly",
            "build",
            "-Z",
            "build-std=core",
            "--target",
            "bpfel-unknown-none",
            "--manifest-path",
        ])
        .arg(&manifest);
    if release {
        cmd.arg("--release");
    }
    // The ebpf crate has its own .cargo/config.toml; clear any inherited env
    // that might override.
    cmd.env_remove("CARGO_BUILD_TARGET");
    cmd.env_remove("RUSTFLAGS");
    let status = cmd.status().context("spawning cargo for shannon-ebpf")?;
    check_status("shannon-ebpf build", status)
}

fn build_userspace(root: &Path, release: bool) -> Result<()> {
    let mut cmd = Command::new(cargo_cmd());
    cmd.current_dir(root)
        .args(["build", "--package", "shannon"]);
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("spawning cargo for userspace")?;
    check_status("userspace build", status)
}

fn cmd_test(args: &TestArgs) -> Result<()> {
    let root = workspace_root()?;
    let mut cmd = Command::new(cargo_cmd());
    cmd.current_dir(&root).args(["test", "--workspace"]);
    for a in &args.rest {
        cmd.arg(a);
    }
    check_status("cargo test", cmd.status()?)
}

fn cmd_lint() -> Result<()> {
    let root = workspace_root()?;
    let host_status = Command::new(cargo_cmd())
        .current_dir(&root)
        .args(["clippy", "--workspace", "--all-targets", "--", "-Dwarnings"])
        .status()?;
    check_status("clippy (userspace)", host_status)?;
    let ebpf_status = Command::new(cargo_cmd())
        .current_dir(root.join("shannon-ebpf"))
        .args([
            "+nightly",
            "clippy",
            "-Z",
            "build-std=core",
            "--target",
            "bpfel-unknown-none",
            "--",
            "-Dwarnings",
        ])
        .status()?;
    check_status("clippy (ebpf)", ebpf_status)
}

fn cmd_fmt(check: bool) -> Result<()> {
    let root = workspace_root()?;
    let mut user = Command::new(cargo_cmd());
    user.current_dir(&root).args(["fmt", "--all"]);
    if check {
        user.arg("--check");
    }
    check_status("fmt (userspace)", user.status()?)?;

    let mut ebpf = Command::new(cargo_cmd());
    ebpf.current_dir(root.join("shannon-ebpf"))
        .args(["+nightly", "fmt"]);
    if check {
        ebpf.arg("--check");
    }
    check_status("fmt (ebpf)", ebpf.status()?)
}

fn cmd_run(args: &RunArgs) -> Result<()> {
    cmd_build(&BuildArgs {
        release: args.release,
        ebpf_only: false,
        userspace_only: false,
    })?;
    let root = workspace_root()?;
    let bin = root
        .join("target")
        .join(if args.release { "release" } else { "debug" })
        .join("shannon");
    let mut cmd = Command::new(&bin);
    for a in &args.rest {
        cmd.arg(a);
    }
    check_status("shannon", cmd.status()?)
}

fn cmd_clean() -> Result<()> {
    let root = workspace_root()?;
    let host = Command::new(cargo_cmd())
        .current_dir(&root)
        .args(["clean"])
        .status()?;
    check_status("cargo clean", host)?;
    let ebpf = Command::new(cargo_cmd())
        .current_dir(root.join("shannon-ebpf"))
        .args(["+nightly", "clean"])
        .status()?;
    check_status("cargo clean (ebpf)", ebpf)
}
