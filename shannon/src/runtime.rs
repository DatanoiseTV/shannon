//! BPF loader and event pump.
//!
//! The runtime is a thin wrapper around an [`aya::Ebpf`] instance, one
//! attached tracepoint per probe, and a tokio task that drains the shared
//! ring buffer into typed events delivered through a channel.

use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::{HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::{KProbe, TracePoint, UProbe};
use aya::Ebpf;
use tokio::sync::mpsc;

use shannon_common::EventHeader;

use crate::events::{decode, DecodedEvent};

/// The embedded BPF object. Built by `build.rs`.
///
/// `include_bytes!` gives us `&'static [u8; N]` with alignment 1. For aya's
/// parser the alignment doesn't matter, but we re-borrow as `&[u8]` anyway
/// so downstream sees a clean slice.
static SHANNON_EBPF_OBJ: &[u8] = include_bytes!(env!("SHANNON_EBPF_OBJ"));

/// Sanity-logging helper. Debug-only; lets us verify at runtime that the
/// embedded bytes are what we think they are.
fn log_obj_prelude() {
    let prelude: Vec<String> = SHANNON_EBPF_OBJ
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect();
    tracing::debug!(
        bytes_len = SHANNON_EBPF_OBJ.len(),
        magic = prelude.join(" "),
        "embedded BPF object"
    );
}

/// Loaded runtime — hold on to this for the lifetime of shannon.
pub struct Runtime {
    bpf: Ebpf,
    pub events_rx: mpsc::Receiver<DecodedEvent>,
}

/// Process-filtering options applied at BPF-load time.
#[derive(Default, Debug, Clone)]
pub struct FilterSetup {
    /// When non-empty, only events from these TGIDs are emitted.
    pub pids: Vec<u32>,
    /// When true, attach the fork tracepoint so children of any filtered
    /// PID are auto-added at runtime.
    pub follow_children: bool,
    /// Extra binary paths to attach libssl / libsqlite3 uprobes to.
    /// Per-symbol best-effort — missing symbols silently skip.
    pub attach_bins: Vec<std::path::PathBuf>,
}

impl Runtime {
    /// Load the embedded BPF object, attach all programs, and start the
    /// event pump task. Events are delivered on the returned receiver.
    pub fn start() -> Result<Self> {
        Self::start_with(&FilterSetup::default())
    }

    /// Variant that applies CLI filter options to the BPF maps before the
    /// event pump starts.
    pub fn start_with(filter: &FilterSetup) -> Result<Self> {
        // Growing the memlock ceiling is only required on pre-5.11 kernels,
        // but doing it unconditionally is harmless.
        if let Err(err) = bump_memlock_rlimit() {
            tracing::debug!(%err, "bumping RLIMIT_MEMLOCK failed (ignored)");
        }

        log_obj_prelude();
        // Copy into an owned Vec — aya's ELF parser does pointer-casts that
        // want the backing storage aligned to ≥4. `include_bytes!` gives us
        // static bytes aligned to 1 which confuses the underlying `object`
        // crate on some section types (`.rel*` groups in particular).
        let owned = SHANNON_EBPF_OBJ.to_vec();
        let mut bpf = Ebpf::load(&owned).context("loading BPF object")?;

        // Tell the kernel who we are so SELF_PID filtering works.
        set_self_pid(&mut bpf)?;

        // Populate PID_FILTER (sentinel key 0 means "filter active").
        if !filter.pids.is_empty() {
            set_pid_filter(&mut bpf, &filter.pids)?;
        }

        // Attach probes. Each call is separate so errors point at the
        // specific probe that failed, not the whole batch.
        attach_kprobe(&mut bpf, "tcp_v4_connect", "tcp_v4_connect")?;
        attach_kprobe(&mut bpf, "tcp_v6_connect", "tcp_v6_connect")?;
        attach_tracepoint(
            &mut bpf,
            "inet_sock_set_state",
            "sock",
            "inet_sock_set_state",
        )?;
        attach_kprobe(&mut bpf, "tcp_sendmsg", "tcp_sendmsg")?;
        attach_kprobe(&mut bpf, "tcp_recvmsg", "tcp_recvmsg")?;
        attach_kretprobe(&mut bpf, "tcp_recvmsg_ret", "tcp_recvmsg")?;
        // UDP payload capture — both directions. udp_sendmsg uses the
        // same iovec/sock layout as tcp_sendmsg; recv needs a kretprobe
        // because the user buffer + msg_name are both populated on
        // return, not at entry.
        attach_kprobe(&mut bpf, "udp_sendmsg", "udp_sendmsg")?;
        attach_kprobe(&mut bpf, "udp_recvmsg", "udp_recvmsg")?;
        attach_kretprobe(&mut bpf, "udp_recvmsg_ret", "udp_recvmsg")?;

        if filter.follow_children {
            attach_tracepoint(
                &mut bpf,
                "sched_process_fork",
                "sched",
                "sched_process_fork",
            )?;
        }

        // TLS: attach to every libssl we can find on the host. Missing is
        // a warning, not a fatal error — a box without TLS libs is still
        // useful for plaintext observation.
        for libssl in libssl_candidates() {
            if let Err(err) = attach_libssl(&mut bpf, &libssl) {
                tracing::warn!(path = %libssl.display(), %err, "skipping libssl uprobes");
            } else {
                tracing::info!(path = %libssl.display(), "attached libssl uprobes");
            }
        }

        // GnuTLS: same dynamic-library pattern. curl-gnutls, wget,
        // and many GUI apps link against this rather than libssl.
        for libgnutls in libgnutls_candidates() {
            if let Err(err) = attach_libgnutls(&mut bpf, &libgnutls) {
                tracing::warn!(path = %libgnutls.display(), %err, "skipping libgnutls uprobes");
            } else {
                tracing::info!(path = %libgnutls.display(), "attached libgnutls uprobes");
            }
        }

        // libsqlite3: same pattern — attach to dynamic library
        // installations. Statically-linked sqlite (Python, sqlite3 CLI,
        // app bundles) is a follow-up via per-binary symbol scan.
        for libsqlite in libsqlite3_candidates() {
            if let Err(err) = attach_libsqlite3(&mut bpf, &libsqlite) {
                tracing::warn!(path = %libsqlite.display(), %err,
                    "skipping libsqlite3 uprobes");
            } else {
                tracing::info!(path = %libsqlite.display(), "attached libsqlite3 uprobes");
            }
        }

        // Auto-discovered libs from /proc/*/maps. Picks up Snap /
        // Flatpak bundles, container bind-mounts, custom installs in
        // /opt or /home that the hardcoded candidate lists miss.
        // Already-attached canonical paths are skipped silently inside
        // the best-effort attachers (aya rejects double-attach with a
        // clear error which we route to debug-level logs).
        let (extra_ssl, extra_gnutls, extra_sqlite) = discover_loaded_libs();
        for path in extra_ssl {
            let n = attach_libssl_best_effort(&mut bpf, &path);
            if n > 0 {
                tracing::info!(path = %path.display(), syms = n, "attached libssl uprobes (auto)");
            }
        }
        for path in extra_gnutls {
            let n = attach_libgnutls_best_effort(&mut bpf, &path);
            if n > 0 {
                tracing::info!(path = %path.display(), syms = n, "attached libgnutls uprobes (auto)");
            }
        }
        for path in extra_sqlite {
            let n = attach_libsqlite3_best_effort(&mut bpf, &path);
            if n > 0 {
                tracing::info!(path = %path.display(), syms = n, "attached libsqlite3 uprobes (auto)");
            }
        }

        // Operator-supplied binaries (statically-linked libssl or
        // libsqlite3 targets, Go apps bundling their own TLS, …).
        // Best-effort per-symbol: binaries that only export one of
        // the two sets still get partial coverage.
        for bin in &filter.attach_bins {
            let loaded_ssl = attach_libssl_best_effort(&mut bpf, bin);
            let loaded_gnutls = attach_libgnutls_best_effort(&mut bpf, bin);
            let loaded_sqlite = attach_libsqlite3_best_effort(&mut bpf, bin);
            tracing::info!(
                path = %bin.display(),
                ssl_syms = loaded_ssl,
                gnutls_syms = loaded_gnutls,
                sqlite_syms = loaded_sqlite,
                "attached uprobes to user-specified binary",
            );
        }

        // Spin up the ring-buffer reader.
        let (tx, rx) = mpsc::channel::<DecodedEvent>(4096);
        spawn_ringbuf_reader(&mut bpf, tx)?;

        Ok(Self { bpf, events_rx: rx })
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let lim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: setrlimit is always-safe; we pass a valid pointer.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn set_self_pid(bpf: &mut Ebpf) -> Result<()> {
    // `aya::maps::HashMap::try_from` borrows mutably, and the BPF side uses
    // the sentinel key `0` in PID_FILTER to mean "filter active". Populate
    // SELF_PID with our own tgid so the BPF side can skip our own traffic.
    let mut self_pid: BpfHashMap<&mut MapData, u32, u8> =
        BpfHashMap::try_from(bpf.map_mut("SELF_PID").context("map SELF_PID missing")?)?;
    let tgid = std::process::id();
    self_pid
        .insert(tgid, 1u8, 0)
        .context("writing SELF_PID entry")?;
    Ok(())
}

fn set_pid_filter(bpf: &mut Ebpf, pids: &[u32]) -> Result<()> {
    let mut filter: BpfHashMap<&mut MapData, u32, u8> = BpfHashMap::try_from(
        bpf.map_mut("PID_FILTER")
            .context("map PID_FILTER missing")?,
    )?;
    // Sentinel u32::MAX means "filter active" — we can't use 0 because
    // softirq context reports tgid=0 and would collide.
    filter
        .insert(u32::MAX, 1u8, 0)
        .context("writing PID_FILTER sentinel")?;
    for &pid in pids {
        filter
            .insert(pid, 1u8, 0)
            .with_context(|| format!("writing PID_FILTER[{pid}]"))?;
    }
    Ok(())
}

fn attach_tracepoint(bpf: &mut Ebpf, program: &str, category: &str, name: &str) -> Result<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(program)
        .with_context(|| format!("program {program} not in BPF object"))?
        .try_into()
        .with_context(|| format!("program {program} is not a TracePoint"))?;
    prog.load().with_context(|| format!("loading {program}"))?;
    prog.attach(category, name)
        .with_context(|| format!("attaching {program} to {category}:{name}"))?;
    Ok(())
}

fn attach_kprobe(bpf: &mut Ebpf, program: &str, function: &str) -> Result<()> {
    let prog: &mut KProbe = bpf
        .program_mut(program)
        .with_context(|| format!("program {program} not in BPF object"))?
        .try_into()
        .with_context(|| format!("program {program} is not a KProbe"))?;
    prog.load().with_context(|| format!("loading {program}"))?;
    prog.attach(function, 0)
        .with_context(|| format!("attaching {program} to kernel function {function}"))?;
    Ok(())
}

fn attach_kretprobe(bpf: &mut Ebpf, program: &str, function: &str) -> Result<()> {
    use aya::programs::KProbe;
    let prog: &mut KProbe = bpf
        .program_mut(program)
        .with_context(|| format!("program {program} not in BPF object"))?
        .try_into()
        .with_context(|| format!("program {program} is not a KProbe"))?;
    prog.load().with_context(|| format!("loading {program}"))?;
    prog.attach(function, 0)
        .with_context(|| format!("attaching {program} to kernel function {function} (ret)"))?;
    Ok(())
}

/// Where libssl might live. We walk a known set and deduplicate by
/// canonical path — many distros symlink `/lib/` to `/usr/lib/` so the
/// same inode appears twice. A given BPF program can only be loaded
/// once, so trying both entries would fail the second.
fn libssl_candidates() -> Vec<std::path::PathBuf> {
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut out = Vec::new();
    for raw in [
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        "/lib64/libssl.so.3",
        "/lib64/libssl.so.1.1",
    ] {
        let p = PathBuf::from(raw);
        let Ok(canon) = p.canonicalize() else {
            continue;
        };
        if seen.insert(canon.clone()) {
            out.push(p);
        }
    }
    out
}

/// Walk `/proc/*/maps` and collect every unique mapped library path that
/// looks like one we know how to probe. Returns a triple of (libssl,
/// libgnutls, libsqlite3) canonical paths — one entry per inode, so the
/// caller can attach without per-version dedup.
///
/// Catches Snap / Flatpak / container bind-mounts / `/opt` installs that
/// the hardcoded `lib*_candidates()` lists don't know about. Failures
/// reading `/proc/<pid>/maps` (process exiting, permission denied for
/// non-root readers of foreign PIDs) are silently skipped.
#[allow(clippy::type_complexity)]
fn discover_loaded_libs() -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    let mut ssl: BTreeSet<PathBuf> = BTreeSet::new();
    let mut gnutls: BTreeSet<PathBuf> = BTreeSet::new();
    let mut sqlite: BTreeSet<PathBuf> = BTreeSet::new();

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        if !name_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let maps = entry.path().join("maps");
        let Ok(content) = std::fs::read_to_string(&maps) else {
            continue;
        };
        for line in content.lines() {
            // Each line: "addr perms offset dev inode pathname"; pathname
            // is everything after the last whitespace cluster, can contain
            // spaces ("(deleted)" etc.). Splitting on whitespace n times
            // is fine for our matching since we only need it to *contain*
            // the substring.
            let Some(path_str) = line.split_whitespace().nth(5) else {
                continue;
            };
            // Skip pseudo-mappings.
            if path_str.starts_with('[') || path_str == "(deleted)" {
                continue;
            }
            let basename = path_str.rsplit('/').next().unwrap_or(path_str);
            let kind = if basename.starts_with("libssl.so") {
                Some(&mut ssl)
            } else if basename.starts_with("libgnutls.so") {
                Some(&mut gnutls)
            } else if basename.starts_with("libsqlite3.so") {
                Some(&mut sqlite)
            } else {
                None
            };
            if let Some(set) = kind {
                let p = PathBuf::from(path_str);
                if let Ok(canon) = p.canonicalize() {
                    set.insert(canon);
                }
            }
        }
    }
    (
        ssl.into_iter().collect(),
        gnutls.into_iter().collect(),
        sqlite.into_iter().collect(),
    )
}

fn attach_libssl(bpf: &mut Ebpf, path: &std::path::Path) -> Result<()> {
    for (program, symbol, ret) in [
        ("ssl_write", "SSL_write", false),
        ("ssl_write_ex", "SSL_write_ex", false),
        ("ssl_read", "SSL_read", false),
        ("ssl_read_ret", "SSL_read", true),
        ("ssl_read_ex", "SSL_read_ex", false),
        ("ssl_read_ex_ret", "SSL_read_ex", true),
    ] {
        attach_uprobe(bpf, program, symbol, path, ret)?;
    }
    Ok(())
}

/// Common installed paths for libgnutls. The Debian/Ubuntu SONAME is
/// `libgnutls.so.30`; older RHEL/Fedora carries the same.
fn libgnutls_candidates() -> Vec<std::path::PathBuf> {
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut out = Vec::new();
    for raw in [
        "/lib/x86_64-linux-gnu/libgnutls.so.30",
        "/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
        "/usr/lib64/libgnutls.so.30",
        "/lib64/libgnutls.so.30",
    ] {
        let p = PathBuf::from(raw);
        let Ok(canon) = p.canonicalize() else {
            continue;
        };
        if seen.insert(canon.clone()) {
            out.push(p);
        }
    }
    out
}

fn attach_libgnutls(bpf: &mut Ebpf, path: &std::path::Path) -> Result<()> {
    for (program, symbol, ret) in [
        ("gnutls_send", "gnutls_record_send", false),
        ("gnutls_recv", "gnutls_record_recv", false),
        ("gnutls_recv_ret", "gnutls_record_recv", true),
    ] {
        attach_uprobe(bpf, program, symbol, path, ret)?;
    }
    Ok(())
}

/// Best-effort libgnutls attach for operator-supplied binaries; mirrors
/// `attach_libssl_best_effort` so a `--attach-bin` target that statically
/// links GnuTLS still gets coverage.
fn attach_libgnutls_best_effort(bpf: &mut Ebpf, path: &std::path::Path) -> usize {
    let mut ok = 0usize;
    for (program, symbol, _ret) in [
        ("gnutls_send", "gnutls_record_send", false),
        ("gnutls_recv", "gnutls_record_recv", false),
        ("gnutls_recv_ret", "gnutls_record_recv", true),
    ] {
        match attach_uprobe_quiet(bpf, program, symbol, path) {
            Ok(()) => ok += 1,
            Err(err) => tracing::debug!(
                path = %path.display(), program, %err,
                "uprobe attach miss — symbol probably not in binary",
            ),
        }
    }
    ok
}

/// Common installed paths for libsqlite3. Same dedup-by-canonical
/// approach as libssl since `/lib` and `/usr/lib` are symlinks on
/// every modern distro.
fn libsqlite3_candidates() -> Vec<std::path::PathBuf> {
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut out = Vec::new();
    for raw in [
        "/lib/x86_64-linux-gnu/libsqlite3.so.0",
        "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0",
        "/usr/lib64/libsqlite3.so.0",
        "/lib64/libsqlite3.so.0",
    ] {
        let p = PathBuf::from(raw);
        let Ok(canon) = p.canonicalize() else {
            continue;
        };
        if seen.insert(canon.clone()) {
            out.push(p);
        }
    }
    out
}

fn attach_libsqlite3(bpf: &mut Ebpf, path: &std::path::Path) -> Result<()> {
    for (program, symbol) in [
        ("sqlite_prepare_v2", "sqlite3_prepare_v2"),
        ("sqlite_exec", "sqlite3_exec"),
    ] {
        attach_uprobe(bpf, program, symbol, path, false)?;
    }
    Ok(())
}

/// Best-effort libssl uprobe attach: tries each symbol individually
/// and skips silently when the symbol isn't exported by the target.
/// Returns the count of symbols that attached. Use for operator-
/// supplied `--attach-bin` paths where the binary may or may not
/// contain the TLS library we probe.
fn attach_libssl_best_effort(bpf: &mut Ebpf, path: &std::path::Path) -> usize {
    let mut ok = 0usize;
    for (program, symbol, _ret) in [
        ("ssl_write", "SSL_write", false),
        ("ssl_write_ex", "SSL_write_ex", false),
        ("ssl_read", "SSL_read", false),
        ("ssl_read_ret", "SSL_read", true),
        ("ssl_read_ex", "SSL_read_ex", false),
        ("ssl_read_ex_ret", "SSL_read_ex", true),
    ] {
        match attach_uprobe_quiet(bpf, program, symbol, path) {
            Ok(()) => ok += 1,
            Err(err) => tracing::debug!(
                path = %path.display(), program, %err,
                "uprobe attach miss — symbol probably not in binary",
            ),
        }
    }
    ok
}

/// Best-effort libsqlite3 uprobe attach; see [`attach_libssl_best_effort`].
fn attach_libsqlite3_best_effort(bpf: &mut Ebpf, path: &std::path::Path) -> usize {
    let mut ok = 0usize;
    for (program, symbol) in [
        ("sqlite_prepare_v2", "sqlite3_prepare_v2"),
        ("sqlite_exec", "sqlite3_exec"),
    ] {
        match attach_uprobe_quiet(bpf, program, symbol, path) {
            Ok(()) => ok += 1,
            Err(err) => tracing::debug!(
                path = %path.display(), program, %err,
                "uprobe attach miss — symbol probably not in binary",
            ),
        }
    }
    ok
}

/// Like [`attach_uprobe`] but without the error-context wrapping so
/// callers can treat "symbol absent" as a soft miss rather than an
/// operator-facing failure.
fn attach_uprobe_quiet(
    bpf: &mut Ebpf,
    program: &str,
    function: &str,
    target: &std::path::Path,
) -> Result<()> {
    let prog: &mut UProbe = bpf
        .program_mut(program)
        .context("program missing from BPF object")?
        .try_into()
        .context("program is not a UProbe")?;
    // Loading a program is idempotent per-aya — but after a failed
    // attach the program may already be in the loaded state. Swallow
    // the "already loaded" case.
    let _ = prog.load();
    prog.attach(Some(function), 0, target, None)
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

fn attach_uprobe(
    bpf: &mut Ebpf,
    program: &str,
    function: &str,
    target: &std::path::Path,
    is_ret: bool,
) -> Result<()> {
    let prog: &mut UProbe = bpf
        .program_mut(program)
        .with_context(|| format!("program {program} not in BPF object"))?
        .try_into()
        .with_context(|| format!("program {program} is not a UProbe"))?;
    prog.load().with_context(|| format!("loading {program}"))?;
    let _ = is_ret; // aya picks uprobe vs uretprobe from the program type,
                    // which in turn comes from the #[uprobe] / #[uretprobe] attribute on
                    // the BPF side — the `ret` flag here is informational for logging.
    prog.attach(Some(function), 0, target, None)
        .with_context(|| {
            format!(
                "attaching {program} to {} in {}",
                function,
                target.display()
            )
        })?;
    Ok(())
}

fn spawn_ringbuf_reader(bpf: &mut Ebpf, tx: mpsc::Sender<DecodedEvent>) -> Result<()> {
    let ring = RingBuf::try_from(bpf.take_map("EVENTS").context("map EVENTS missing")?)?;
    let ring = Arc::new(parking_lot::Mutex::new(ring));

    // Synchronous drain driven by tokio's blocking task; the ring buffer API
    // in aya 0.13 is sync, and events are small so a single background
    // thread is enough.
    std::thread::Builder::new()
        .name("shannon-ringbuf".into())
        .spawn(move || {
            loop {
                let mut guard = ring.lock();
                while let Some(record) = guard.next() {
                    if record.len() < size_of::<EventHeader>() {
                        tracing::warn!(len = record.len(), "ringbuf record smaller than header");
                        continue;
                    }
                    match decode(&record) {
                        Ok(ev) => {
                            // If the channel is closed, we're shutting down.
                            if tx.blocking_send(ev).is_err() {
                                return;
                            }
                        }
                        Err(err) => tracing::debug!(%err, "decode failed"),
                    }
                }
                drop(guard);
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        })?;
    Ok(())
}
