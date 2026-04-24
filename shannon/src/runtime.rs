//! BPF loader and event pump.
//!
//! The runtime is a thin wrapper around an [`aya::Ebpf`] instance, one
//! attached tracepoint per probe, and a tokio task that drains the shared
//! ring buffer into typed events delivered through a channel.

use std::sync::Arc;

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::{HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::{KProbe, TracePoint, UProbe};
use tokio::sync::mpsc;

use shannon_common::EventHeader;

use crate::events::{DecodedEvent, decode};

/// The embedded BPF object. Built by `build.rs`.
///
/// `include_bytes!` gives us `&'static [u8; N]` with alignment 1. For aya's
/// parser the alignment doesn't matter, but we re-borrow as `&[u8]` anyway
/// so downstream sees a clean slice.
static SHANNON_EBPF_OBJ: &[u8] = include_bytes!(env!("SHANNON_EBPF_OBJ"));

/// Sanity-logging helper. Debug-only; lets us verify at runtime that the
/// embedded bytes are what we think they are.
fn log_obj_prelude() {
    let prelude: Vec<String> =
        SHANNON_EBPF_OBJ.iter().take(8).map(|b| format!("{b:02x}")).collect();
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
        attach_tracepoint(&mut bpf, "inet_sock_set_state", "sock", "inet_sock_set_state")?;
        attach_kprobe(&mut bpf, "tcp_sendmsg", "tcp_sendmsg")?;
        attach_kprobe(&mut bpf, "tcp_recvmsg", "tcp_recvmsg")?;
        attach_kretprobe(&mut bpf, "tcp_recvmsg_ret", "tcp_recvmsg")?;

        if filter.follow_children {
            attach_tracepoint(&mut bpf, "sched_process_fork", "sched", "sched_process_fork")?;
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

        // Spin up the ring-buffer reader.
        let (tx, rx) = mpsc::channel::<DecodedEvent>(4096);
        spawn_ringbuf_reader(&mut bpf, tx)?;

        Ok(Self { bpf, events_rx: rx })
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let lim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
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
    self_pid.insert(tgid, 1u8, 0).context("writing SELF_PID entry")?;
    Ok(())
}

fn set_pid_filter(bpf: &mut Ebpf, pids: &[u32]) -> Result<()> {
    let mut filter: BpfHashMap<&mut MapData, u32, u8> =
        BpfHashMap::try_from(bpf.map_mut("PID_FILTER").context("map PID_FILTER missing")?)?;
    // Sentinel u32::MAX means "filter active" — we can't use 0 because
    // softirq context reports tgid=0 and would collide.
    filter.insert(u32::MAX, 1u8, 0).context("writing PID_FILTER sentinel")?;
    for &pid in pids {
        filter.insert(pid, 1u8, 0).with_context(|| format!("writing PID_FILTER[{pid}]"))?;
    }
    Ok(())
}

fn attach_tracepoint(
    bpf: &mut Ebpf,
    program: &str,
    category: &str,
    name: &str,
) -> Result<()> {
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
        let Ok(canon) = p.canonicalize() else { continue };
        if seen.insert(canon.clone()) {
            out.push(p);
        }
    }
    out
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
    prog.attach(Some(function), 0, target, None).with_context(|| {
        format!("attaching {program} to {} in {}", function, target.display())
    })?;
    Ok(())
}

fn spawn_ringbuf_reader(bpf: &mut Ebpf, tx: mpsc::Sender<DecodedEvent>) -> Result<()> {
    let ring = RingBuf::try_from(bpf.take_map("EVENTS").context("map EVENTS missing")?)?;
    let ring = Arc::new(parking_lot::Mutex::new(ring));

    // Synchronous drain driven by tokio's blocking task; the ring buffer API
    // in aya 0.13 is sync, and events are small so a single background
    // thread is enough.
    std::thread::Builder::new().name("shannon-ringbuf".into()).spawn(move || {
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
