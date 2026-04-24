//! Reverse DNS cache.
//!
//! A simple IP → hostname map that the trace renderer consults to decorate
//! raw addresses with names. Lookups run on a background worker thread so
//! the hot event-render path never blocks on network I/O; the first time
//! we see an IP we return `None` and enqueue the lookup, and subsequent
//! lookups for the same IP will hit the cache.
//!
//! We cap the cache so a long-running session doesn't grow unboundedly.

use std::collections::HashMap;
use std::ffi::CStr;
use std::net::IpAddr;
use std::sync::{
    Arc,
    mpsc::{Receiver, Sender, channel},
};

use parking_lot::Mutex;

/// Max entries kept in the cache. Oldest are evicted on overflow.
const CACHE_CAP: usize = 8192;

/// Sentinel for "lookup in flight / no name found" so we don't re-queue
/// the same IP repeatedly. An empty string means "looked up, no PTR".
const NEGATIVE: &str = "";

#[derive(Clone)]
pub struct DnsCache {
    inner: Arc<Mutex<Inner>>,
    tx: Sender<IpAddr>,
}

struct Inner {
    map: HashMap<IpAddr, Arc<String>>,
    /// FIFO of keys for coarse-grained eviction.
    order: Vec<IpAddr>,
}

impl DnsCache {
    pub fn new() -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            map: HashMap::with_capacity(1024),
            order: Vec::with_capacity(1024),
        }));
        let (tx, rx): (Sender<IpAddr>, Receiver<IpAddr>) = channel();
        let worker = Arc::clone(&inner);
        std::thread::Builder::new()
            .name("shannon-rdns".into())
            .spawn(move || {
                while let Ok(ip) = rx.recv() {
                    let name = reverse_lookup(ip).unwrap_or_default();
                    let mut g = worker.lock();
                    // Only overwrite if the entry is still the "in-flight"
                    // placeholder — a second lookup may have arrived first.
                    if let Some(existing) = g.map.get(&ip).cloned() {
                        if existing.as_str() == NEGATIVE && !name.is_empty() {
                            g.map.insert(ip, Arc::new(name));
                        }
                    }
                }
            })
            .expect("spawn shannon-rdns thread");
        Self { inner, tx }
    }

    /// Return the cached hostname for `ip`, or enqueue a lookup and return
    /// `None`. Never blocks.
    pub fn lookup(&self, ip: IpAddr) -> Option<Arc<String>> {
        let mut g = self.inner.lock();
        if let Some(name) = g.map.get(&ip).cloned() {
            if name.is_empty() { None } else { Some(name) }
        } else {
            // Insert the NEGATIVE placeholder immediately so a later event
            // doesn't re-queue.
            let placeholder = Arc::new(NEGATIVE.to_string());
            g.map.insert(ip, placeholder);
            g.order.push(ip);
            if g.order.len() > CACHE_CAP {
                let old = g.order.remove(0);
                g.map.remove(&old);
            }
            drop(g);
            let _ = self.tx.send(ip);
            None
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocking reverse DNS via `getnameinfo`. Returns `None` on any error or
/// when the PTR lookup produces a name that's just the dotted-quad / hex
/// representation of the IP (which means no real PTR exists).
fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let mut host = [0u8; libc::NI_MAXHOST as usize];
    let rc;
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(octets) },
                sin_zero: [0; 8],
            };
            // SAFETY: well-formed sockaddr_in + valid out-buffer.
            rc = unsafe {
                libc::getnameinfo(
                    std::ptr::from_ref(&sa).cast(),
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr().cast(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            };
        }
        IpAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: v6.octets() },
                sin6_scope_id: 0,
            };
            // SAFETY: well-formed sockaddr_in6 + valid out-buffer.
            rc = unsafe {
                libc::getnameinfo(
                    std::ptr::from_ref(&sa).cast(),
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr().cast(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            };
        }
    }
    if rc != 0 {
        return None;
    }
    // SAFETY: getnameinfo null-terminates on success.
    let cstr = unsafe { CStr::from_ptr(host.as_ptr().cast()) };
    let s = cstr.to_str().ok()?.to_string();
    if s.is_empty() { None } else { Some(s) }
}
