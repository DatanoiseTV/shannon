//! Cgroup-id → container/pod name resolver.
//!
//! Every event shannon emits carries the kernel's `cgroup_id` (fetched
//! via `bpf_get_current_cgroup_id`). Humans want the container / pod
//! name, not the 64-bit id. We walk `/sys/fs/cgroup` at startup and
//! periodically refresh, building a map from cgroup inode number to
//! `(runtime, name)` by pattern-matching the hierarchical cgroup path.
//!
//! Supported runtimes: Docker, containerd, CRI-O, Podman. Kubernetes
//! pods are recognised via the `kubepods` root path.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;

/// `(runtime, short_name)` — runtime is `"docker"`, `"containerd"`,
/// `"cri-o"`, `"podman"`, `"k8s"` or `"systemd"`; `short_name` is the
/// human-friendly container / pod / unit name (not the full cgroup path).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerInfo {
    pub runtime: &'static str,
    pub name: String,
}

#[derive(Clone, Default)]
pub struct ContainerResolver {
    map: Arc<RwLock<HashMap<u64, ContainerInfo>>>,
}

impl ContainerResolver {
    pub fn new() -> Self {
        let this = Self::default();
        this.refresh();
        this
    }

    /// Look up a cgroup id. Returns `None` if unknown — caller can
    /// display the bare id or an empty string.
    pub fn lookup(&self, cgroup_id: u64) -> Option<ContainerInfo> {
        self.map.read().get(&cgroup_id).cloned()
    }

    pub fn len(&self) -> usize {
        self.map.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.read().is_empty()
    }

    /// Walk `/sys/fs/cgroup` once and rebuild the map.
    pub fn refresh(&self) {
        let mut fresh = HashMap::new();
        let root = Path::new("/sys/fs/cgroup");
        if !root.exists() {
            return;
        }
        let kube = K8sPodCache::build();
        walk(root, root, &kube, &mut fresh);
        *self.map.write() = fresh;
    }

    /// Spawn a background thread that refreshes every `interval`.
    /// Consumers hold an [`Arc<ContainerResolver>`]; the thread exits
    /// automatically when the last Arc is dropped.
    pub fn spawn_refresher(self: Arc<Self>, interval: Duration) {
        std::thread::Builder::new()
            .name("shannon-cgroup-refresh".into())
            .spawn(move || loop {
                std::thread::sleep(interval);
                if Arc::strong_count(&self) <= 1 {
                    return;
                }
                self.refresh();
            })
            .expect("spawn cgroup refresh thread");
    }
}

fn walk(base: &Path, dir: &Path, kube: &K8sPodCache, out: &mut HashMap<u64, ContainerInfo>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_dir() {
            continue;
        }
        let ino = meta.ino();
        if let Some(info) = classify(base, &path, kube) {
            out.insert(ino, info);
        }
        walk(base, &path, kube, out);
    }
}

fn classify(base: &Path, path: &Path, kube: &K8sPodCache) -> Option<ContainerInfo> {
    let rel = path.strip_prefix(base).ok()?;
    let s = rel.to_string_lossy();
    if s.is_empty() {
        return None;
    }

    // Docker: /docker/<64-hex>.
    if let Some(id) = first_segment_after(&s, "docker/") {
        if id.len() >= 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(ContainerInfo {
                runtime: "docker",
                name: id[..12].to_string(),
            });
        }
    }

    // Kubernetes pods under kubepods.slice/...
    // e.g.   kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<hex>.scope
    if s.contains("kubepods") {
        // Walk from leaf up: pick the deepest `.scope` or `.slice` as the container.
        if let Some(leaf) = path.file_name().and_then(|n| n.to_str()) {
            let pod = enclosing_pod(path).and_then(|uid| kube.lookup(&uid));
            // cri-containerd-<hex>.scope  -> containerd <hex>[:12]
            if let Some(hex) = leaf
                .strip_prefix("cri-containerd-")
                .and_then(|s| s.strip_suffix(".scope"))
            {
                if hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(ContainerInfo {
                        runtime: "containerd",
                        name: container_name(pod.as_ref(), hex),
                    });
                }
            }
            // crio-<hex>.scope
            if let Some(hex) = leaf
                .strip_prefix("crio-")
                .and_then(|s| s.strip_suffix(".scope"))
            {
                if hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(ContainerInfo {
                        runtime: "cri-o",
                        name: container_name(pod.as_ref(), hex),
                    });
                }
            }
            // docker-<hex>.scope
            if let Some(hex) = leaf
                .strip_prefix("docker-")
                .and_then(|s| s.strip_suffix(".scope"))
            {
                if hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(ContainerInfo {
                        runtime: "docker",
                        name: container_name(pod.as_ref(), hex),
                    });
                }
            }
            // kubepods-*-pod<uid>.slice — the pod itself (no container yet).
            if let Some(uid) = leaf.strip_prefix("kubepods-").and_then(kubepod_uid) {
                let name = kube
                    .lookup(&uid)
                    .map(|p| format!("{}/{}", p.namespace, p.pod))
                    .unwrap_or_else(|| format!("pod:{uid}"));
                return Some(ContainerInfo {
                    runtime: "k8s",
                    name,
                });
            }
        }
    }

    // Podman: libpod-<hex>.scope
    if let Some(leaf) = path.file_name().and_then(|n| n.to_str()) {
        if let Some(hex) = leaf
            .strip_prefix("libpod-")
            .and_then(|s| s.strip_suffix(".scope"))
        {
            if hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(ContainerInfo {
                    runtime: "podman",
                    name: hex[..hex.len().min(12)].to_string(),
                });
            }
        }
        // systemd units — catch common service cgroups so we have something
        // to display even outside containers.
        if leaf.ends_with(".service") && leaf.len() > ".service".len() {
            let name = leaf.trim_end_matches(".service").to_string();
            return Some(ContainerInfo {
                runtime: "systemd",
                name,
            });
        }
    }

    None
}

fn first_segment_after<'a>(s: &'a str, marker: &str) -> Option<&'a str> {
    let idx = s.find(marker)?;
    let tail = &s[idx + marker.len()..];
    let end = tail.find('/').unwrap_or(tail.len());
    Some(&tail[..end])
}

fn kubepod_uid(s: &str) -> Option<String> {
    // Pattern: "<qos>-pod<uid>.slice"
    let (_qos, after) = s.split_once("-pod")?;
    let uid = after.trim_end_matches(".slice");
    if uid
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == '_' || c == '-')
    {
        Some(uid.to_string())
    } else {
        None
    }
}

/// Walk `path` upward looking for the enclosing `kubepods-...-pod<uid>.slice`
/// component. Used by container entries to discover their pod.
fn enclosing_pod(path: &Path) -> Option<String> {
    for component in path.iter().rev() {
        let s = component.to_str()?;
        if let Some(uid) = s.strip_prefix("kubepods-").and_then(kubepod_uid) {
            return Some(uid);
        }
    }
    None
}

/// Compose a friendly container name. With a known pod the container shows
/// up as `<ns>/<pod>/<short-id>`; otherwise we fall back to the bare runtime
/// hex prefix.
fn container_name(pod: Option<&PodMeta>, hex: &str) -> String {
    let short = &hex[..hex.len().min(12)];
    match pod {
        Some(p) => format!("{}/{}/{short}", p.namespace, p.pod),
        None => short.to_string(),
    }
}

/// In-memory snapshot of `/var/log/pods/`. The kubelet creates one
/// directory per pod here named `<namespace>_<pod-name>_<uid>` — we
/// invert that to map UID → (namespace, pod). The UID in this path
/// uses dashes; cgroup paths use underscores in the same position, so
/// `lookup` normalises before matching.
#[derive(Default)]
struct K8sPodCache {
    by_uid: HashMap<String, PodMeta>,
}

#[derive(Clone)]
struct PodMeta {
    namespace: String,
    pod: String,
}

impl K8sPodCache {
    fn build() -> Self {
        let mut by_uid: HashMap<String, PodMeta> = HashMap::new();
        let root = Path::new("/var/log/pods");
        let Ok(entries) = fs::read_dir(root) else {
            return Self { by_uid };
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            // Format: <ns>_<pod>_<uid>. Pod names may contain '_' so split
            // from the right: last `_` separates uid; the next `_` from the
            // left of the remainder separates namespace from pod name.
            let Some((ns_pod, uid)) = name.rsplit_once('_') else {
                continue;
            };
            let Some((namespace, pod)) = ns_pod.split_once('_') else {
                continue;
            };
            by_uid.insert(
                uid.to_string(),
                PodMeta {
                    namespace: namespace.to_string(),
                    pod: pod.to_string(),
                },
            );
        }
        Self { by_uid }
    }

    fn lookup(&self, cgroup_uid: &str) -> Option<PodMeta> {
        // Cgroup paths spell the UID with underscores; the kubelet's own
        // log layout keeps the original dashes.
        let normalised = cgroup_uid.replace('_', "-");
        self.by_uid.get(&normalised).cloned()
    }
}

impl ContainerInfo {
    pub fn render(&self) -> String {
        format!("[{}/{}]", self.runtime, self.name)
    }
}

/// Resolve `/proc/<pid>/cgroup` to the preferred container for a process.
/// Parses the unified cgroup v2 line and returns the cgroup path (which
/// the resolver's map can translate). Returns `None` if the process has
/// no cgroup or the file isn't readable.
pub fn pid_cgroup_path(pid: u32) -> Option<PathBuf> {
    let s = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    // v2 format: single line "0::/cgroup/path"
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let trimmed = rest.trim();
            if !trimmed.is_empty() {
                return Some(Path::new("/sys/fs/cgroup").join(trimmed.trim_start_matches('/')));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_docker() {
        let base = Path::new("/sys/fs/cgroup");
        let p = base.join("docker/123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let info = classify(base, &p, &K8sPodCache::default()).expect("docker match");
        assert_eq!(info.runtime, "docker");
        assert_eq!(info.name, "123456789abc");
    }

    #[test]
    fn classifies_podman() {
        let base = Path::new("/sys/fs/cgroup");
        let p =
            base.join("user.slice/user-1000.slice/libpod-abcdef1234567890abcdef1234567890.scope");
        let info = classify(base, &p, &K8sPodCache::default()).expect("podman match");
        assert_eq!(info.runtime, "podman");
    }

    #[test]
    fn classifies_kubepods_containerd() {
        let base = Path::new("/sys/fs/cgroup");
        let p = base.join(
            "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod11e69ae7_6bf8.slice/cri-containerd-deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcd.scope",
        );
        let info = classify(base, &p, &K8sPodCache::default()).expect("containerd match");
        assert_eq!(info.runtime, "containerd");
    }

    #[test]
    fn classifies_systemd_service() {
        let base = Path::new("/sys/fs/cgroup");
        let p = base.join("system.slice/nginx.service");
        let info = classify(base, &p, &K8sPodCache::default()).expect("systemd match");
        assert_eq!(info.runtime, "systemd");
        assert_eq!(info.name, "nginx");
    }

    #[test]
    fn unknown_path_is_none() {
        let base = Path::new("/sys/fs/cgroup");
        let p = base.join("some/random/dir");
        assert!(classify(base, &p, &K8sPodCache::default()).is_none());
    }

    #[test]
    fn k8s_pod_uid_is_upgraded_to_friendly_name() {
        let base = Path::new("/sys/fs/cgroup");
        let p = base.join(
            "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod11e69ae7_6bf8_4cf8_aaaa_111122223333.slice",
        );
        let kube = K8sPodCache {
            by_uid: HashMap::from([(
                "11e69ae7-6bf8-4cf8-aaaa-111122223333".to_string(),
                PodMeta {
                    namespace: "payments".to_string(),
                    pod: "billing-7d8c".to_string(),
                },
            )]),
        };
        let info = classify(base, &p, &kube).expect("k8s match");
        assert_eq!(info.runtime, "k8s");
        assert_eq!(info.name, "payments/billing-7d8c");
    }

    #[test]
    fn k8s_container_name_includes_pod_context() {
        let base = Path::new("/sys/fs/cgroup");
        let p = base.join(
            "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod11e69ae7_6bf8_4cf8_aaaa_111122223333.slice/cri-containerd-deadbeefcafebabe0123456789abcdef.scope",
        );
        let kube = K8sPodCache {
            by_uid: HashMap::from([(
                "11e69ae7-6bf8-4cf8-aaaa-111122223333".to_string(),
                PodMeta {
                    namespace: "payments".to_string(),
                    pod: "billing-7d8c".to_string(),
                },
            )]),
        };
        let info = classify(base, &p, &kube).expect("k8s container match");
        assert_eq!(info.runtime, "containerd");
        assert_eq!(info.name, "payments/billing-7d8c/deadbeefcafe");
    }

    #[test]
    fn k8s_container_without_pod_cache_falls_back_to_hex() {
        let base = Path::new("/sys/fs/cgroup");
        let p = base.join(
            "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod11e69ae7_6bf8_4cf8_aaaa_111122223333.slice/cri-containerd-deadbeefcafebabe0123456789abcdef.scope",
        );
        let info = classify(base, &p, &K8sPodCache::default()).expect("match");
        assert_eq!(info.runtime, "containerd");
        assert_eq!(info.name, "deadbeefcafe");
    }
}
