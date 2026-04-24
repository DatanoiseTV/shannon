//! `shannon doctor` — environment diagnostics with copy-pasteable remediation.
//!
//! The purpose is to turn "shannon didn't work" into "here is the exact
//! command to fix it". Every check prints its status and, on failure, the
//! one-line fix.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::AppError;
use crate::cli::Cli;

/// Runs all checks and prints the report. Exits non-zero if any required
/// check failed.
pub fn run(_cli: &Cli) -> anyhow::Result<()> {
    let mut report = Report::default();

    check_kernel(&mut report);
    check_btf(&mut report);
    check_rlimit_memlock(&mut report);
    check_capabilities(&mut report);
    check_libssl(&mut report);
    check_libsqlite3(&mut report);
    check_bpf_fs(&mut report);
    check_kallsyms(&mut report);

    report.print();

    if report.any_required_failed() {
        return Err(AppError::Unsupported("doctor: required checks failed".into()).into());
    }
    Ok(())
}

#[derive(Default)]
struct Report {
    rows: Vec<Row>,
}

struct Row {
    name: &'static str,
    status: Status,
    detail: String,
    fix: Option<String>,
    required: bool,
}

#[derive(PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
}

impl Report {
    fn push(&mut self, row: Row) {
        self.rows.push(row);
    }

    fn any_required_failed(&self) -> bool {
        self.rows.iter().any(|r| r.required && r.status == Status::Fail)
    }

    fn print(&self) {
        let mut out = std::io::stderr().lock();
        for r in &self.rows {
            let sigil = match r.status {
                Status::Ok => "✓",
                Status::Warn => "!",
                Status::Fail => "✗",
            };
            let _ = writeln!(out, "{sigil}  {:<28}  {}", r.name, r.detail);
            if r.status != Status::Ok {
                if let Some(fix) = &r.fix {
                    let _ = writeln!(out, "     fix: {fix}");
                }
            }
        }
    }
}

fn check_kernel(r: &mut Report) {
    let (major, minor) = kernel_version().unwrap_or((0, 0));
    let version_str = format!("{major}.{minor}");
    if major > 5 || (major == 5 && minor >= 8) {
        r.push(Row {
            name: "kernel >= 5.8",
            status: Status::Ok,
            detail: format!("running {version_str}"),
            fix: None,
            required: true,
        });
    } else {
        r.push(Row {
            name: "kernel >= 5.8",
            status: Status::Fail,
            detail: format!("running {version_str}"),
            fix: Some("upgrade your kernel; shannon requires RINGBUF (5.8+)".into()),
            required: true,
        });
    }
}

fn kernel_version() -> Option<(u32, u32)> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let mut parts = release.trim().split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn check_btf(r: &mut Report) {
    let present = Path::new("/sys/kernel/btf/vmlinux").exists();
    r.push(Row {
        name: "kernel BTF",
        status: if present { Status::Ok } else { Status::Fail },
        detail: if present {
            "/sys/kernel/btf/vmlinux present".into()
        } else {
            "/sys/kernel/btf/vmlinux missing".into()
        },
        fix: (!present).then(|| {
            "enable CONFIG_DEBUG_INFO_BTF in your kernel config; most distro kernels have this".into()
        }),
        required: true,
    });
}

fn check_rlimit_memlock(r: &mut Report) {
    // Modern kernels (>= 5.11) don't need this, but older do.
    let fix = "ulimit -l unlimited  # or set LimitMEMLOCK=infinity in the systemd unit";
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit is always-safe; we pass a valid out-pointer.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
    if rc != 0 {
        r.push(Row {
            name: "rlimit memlock",
            status: Status::Warn,
            detail: "could not query rlimit".into(),
            fix: Some(fix.into()),
            required: false,
        });
        return;
    }
    let ok = limit.rlim_cur == u64::MAX || limit.rlim_cur >= 64 * 1024 * 1024;
    r.push(Row {
        name: "rlimit memlock",
        status: if ok { Status::Ok } else { Status::Warn },
        detail: if limit.rlim_cur == u64::MAX {
            "unlimited".into()
        } else {
            format!("{} MiB", limit.rlim_cur / (1024 * 1024))
        },
        fix: (!ok).then(|| fix.into()),
        required: false,
    });
}

fn check_capabilities(r: &mut Report) {
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
        r.push(Row {
            name: "privileges",
            status: Status::Ok,
            detail: "running as root".into(),
            fix: None,
            required: true,
        });
        return;
    }
    // Probe for the capabilities we need.
    let required = [caps::Capability::CAP_BPF, caps::Capability::CAP_PERFMON, caps::Capability::CAP_NET_ADMIN];
    let effective = caps::read(None, caps::CapSet::Effective).unwrap_or_default();
    let missing: Vec<_> = required.iter().filter(|c| !effective.contains(c)).collect();
    if missing.is_empty() {
        r.push(Row {
            name: "privileges",
            status: Status::Ok,
            detail: "CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN present".into(),
            fix: None,
            required: true,
        });
    } else {
        r.push(Row {
            name: "privileges",
            status: Status::Fail,
            detail: format!("missing: {missing:?}"),
            fix: Some(
                "run as root, OR: sudo setcap cap_bpf,cap_perfmon,cap_net_admin+eip $(which shannon)".into(),
            ),
            required: true,
        });
    }
}

fn check_libssl(r: &mut Report) {
    // Non-fatal — shannon works for plaintext even without libssl present;
    // this just warns about reduced TLS visibility.
    let candidates = [
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
    ];
    let found = candidates.iter().find(|p| Path::new(p).exists());
    r.push(Row {
        name: "libssl (for TLS)",
        status: if found.is_some() { Status::Ok } else { Status::Warn },
        detail: found.map_or_else(
            || "not found — TLS via OpenSSL will be unavailable".into(),
            |p| (*p).to_string(),
        ),
        fix: found.is_none().then(|| "apt install libssl3 # or equivalent".into()),
        required: false,
    });
}

fn check_libsqlite3(r: &mut Report) {
    // Non-fatal — shannon's network surface works without sqlite, but
    // SQL capture won't fire if libsqlite3 isn't present.
    let candidates = [
        "/lib/x86_64-linux-gnu/libsqlite3.so.0",
        "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0",
        "/usr/lib64/libsqlite3.so.0",
        "/lib64/libsqlite3.so.0",
    ];
    let found = candidates.iter().find(|p| Path::new(p).exists());
    r.push(Row {
        name: "libsqlite3 (for SQL)",
        status: if found.is_some() { Status::Ok } else { Status::Warn },
        detail: found.map_or_else(
            || "not found — sqlite3_prepare_v2 / exec uprobes will be unavailable".into(),
            |p| (*p).to_string(),
        ),
        fix: found.is_none().then(|| "apt install libsqlite3-0 # or equivalent".into()),
        required: false,
    });
}

fn check_kallsyms(r: &mut Report) {
    // Verify the kernel symbols our kprobes attach to actually exist.
    // Missing symbols here means the kernel was built without TCP/UDP
    // probepoints, or kallsyms is restricted (kptr_restrict).
    let path = "/proc/kallsyms";
    let needed: &[&str] = &[
        "tcp_sendmsg",
        "tcp_recvmsg",
        "udp_sendmsg",
        "udp_recvmsg",
        "tcp_v4_connect",
    ];
    let body = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => {
            r.push(Row {
                name: "kallsyms readable",
                status: Status::Warn,
                detail: format!("cannot read {path}"),
                fix: Some("sudo sysctl kernel.kptr_restrict=0  # for symbol visibility".into()),
                required: false,
            });
            return;
        }
    };
    let missing: Vec<&str> = needed
        .iter()
        .copied()
        .filter(|sym| !body.lines().any(|l| {
            // /proc/kallsyms lines look like "ffffffff814a3e90 T tcp_sendmsg".
            l.split_whitespace().nth(2) == Some(sym)
        }))
        .collect();
    if missing.is_empty() {
        r.push(Row {
            name: "kprobe targets",
            status: Status::Ok,
            detail: format!("found all {} symbols", needed.len()),
            fix: None,
            required: false,
        });
    } else {
        r.push(Row {
            name: "kprobe targets",
            status: Status::Warn,
            detail: format!("missing: {}", missing.join(", ")),
            fix: Some(
                "rebuild kernel with CONFIG_KPROBES + CONFIG_NET; or run with kptr_restrict=0".into(),
            ),
            required: false,
        });
    }
}

fn check_bpf_fs(r: &mut Report) {
    let mounted = fs::metadata("/sys/fs/bpf").is_ok();
    r.push(Row {
        name: "bpffs mount",
        status: if mounted { Status::Ok } else { Status::Warn },
        detail: if mounted {
            "/sys/fs/bpf mounted".into()
        } else {
            "/sys/fs/bpf not mounted".into()
        },
        fix: (!mounted).then(|| "sudo mount -t bpf bpf /sys/fs/bpf".into()),
        required: false,
    });
}
