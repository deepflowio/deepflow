use std::{
    env, fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

use flate2::read::GzDecoder;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelCapability {
    pub bpf_lsm_configured: bool,
    pub bpf_lsm_active: bool,
    pub bpf_kprobe_override_configured: bool,
    pub seccomp_filter_configured: bool,
    pub btf_vmlinux_available: bool,
}

impl KernelCapability {
    pub fn detect() -> Self {
        let proc_root = path_from_env("PROCFS_ROOT", "/proc");
        let sys_root = path_from_env("SYSFS_ROOT", "/sys");
        let boot_root =
            host_sibling_root(&proc_root, "boot").unwrap_or_else(|| PathBuf::from("/boot"));

        Self::detect_from_roots(&proc_root, &sys_root, &boot_root)
    }

    pub fn detect_from_roots(proc_root: &Path, sys_root: &Path, boot_root: &Path) -> Self {
        let lsm_text = fs::read_to_string(sys_root.join("kernel/security/lsm")).unwrap_or_default();
        let config_text = read_kernel_config_from_roots(proc_root, boot_root).unwrap_or_default();
        let bpf_lsm_active = lsm_has_bpf(&lsm_text);

        Self {
            bpf_lsm_configured: config_enabled(&config_text, "CONFIG_BPF_LSM") || bpf_lsm_active,
            bpf_lsm_active,
            bpf_kprobe_override_configured: config_enabled(
                &config_text,
                "CONFIG_BPF_KPROBE_OVERRIDE",
            ),
            seccomp_filter_configured: config_enabled(&config_text, "CONFIG_SECCOMP_FILTER"),
            btf_vmlinux_available: sys_root.join("kernel/btf/vmlinux").exists(),
        }
    }

    pub fn supports_exec_lsm_enforcement(&self) -> bool {
        self.bpf_lsm_configured && self.bpf_lsm_active
    }
}

fn path_from_env(name: &str, default: &str) -> PathBuf {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

fn host_sibling_root(proc_root: &Path, sibling: &str) -> Option<PathBuf> {
    let parent = proc_root.parent()?;
    Some(parent.join(sibling))
}

fn lsm_has_bpf(lsm_text: &str) -> bool {
    lsm_text
        .trim()
        .split(',')
        .map(str::trim)
        .any(|name| name == "bpf")
}

fn config_enabled(config_text: &str, option: &str) -> bool {
    let enabled = format!("{option}=y");
    config_text
        .lines()
        .map(str::trim)
        .any(|line| line == enabled)
}

fn read_kernel_config() -> Option<String> {
    read_kernel_config_from_roots(Path::new("/proc"), Path::new("/boot"))
}

fn read_kernel_config_from_roots(proc_root: &Path, boot_root: &Path) -> Option<String> {
    if let Some(config) = read_boot_kernel_config(proc_root, boot_root) {
        return Some(config);
    }
    read_proc_kernel_config(proc_root)
}

fn read_boot_kernel_config(proc_root: &Path, boot_root: &Path) -> Option<String> {
    let release = fs::read_to_string(proc_root.join("sys/kernel/osrelease")).ok()?;
    let path = boot_root.join(format!("config-{}", release.trim()));
    fs::read_to_string(path).ok()
}

fn read_proc_kernel_config(proc_root: &Path) -> Option<String> {
    let compressed = fs::read(proc_root.join("config.gz")).ok()?;
    decode_gzip(&compressed).ok()
}

fn decode_gzip(bytes: &[u8]) -> Result<String, std::io::Error> {
    let mut decoder = GzDecoder::new(Cursor::new(bytes));
    let mut output = String::new();
    decoder.read_to_string(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lsm_detects_bpf() {
        assert!(lsm_has_bpf("lockdown,capability,yama,apparmor,bpf"));
        assert!(!lsm_has_bpf("lockdown,capability,yama,apparmor"));
    }

    #[test]
    fn parse_config_detects_bpf_lsm() {
        assert!(config_enabled("CONFIG_BPF_LSM=y\n", "CONFIG_BPF_LSM"));
        assert!(!config_enabled(
            "# CONFIG_BPF_LSM is not set\n",
            "CONFIG_BPF_LSM"
        ));
    }

    #[test]
    fn support_exec_lsm_requires_config_and_active_lsm() {
        assert!(KernelCapability {
            bpf_lsm_configured: true,
            bpf_lsm_active: true,
            ..Default::default()
        }
        .supports_exec_lsm_enforcement());

        assert!(!KernelCapability {
            bpf_lsm_configured: true,
            bpf_lsm_active: false,
            ..Default::default()
        }
        .supports_exec_lsm_enforcement());
    }

    #[test]
    fn detect_from_roots_reads_host_sysfs_lsm_in_container() {
        let root = make_temp_root("host-sysfs-lsm");
        let proc_root = root.join("host-proc");
        let sys_root = root.join("host-sys");
        let boot_root = root.join("boot");
        fs::create_dir_all(sys_root.join("kernel/security")).unwrap();
        fs::create_dir_all(sys_root.join("kernel/btf")).unwrap();
        fs::create_dir_all(proc_root.join("sys/kernel")).unwrap();
        fs::write(
            sys_root.join("kernel/security/lsm"),
            "capability,yama,selinux,bpf",
        )
        .unwrap();
        fs::write(sys_root.join("kernel/btf/vmlinux"), b"btf").unwrap();
        fs::write(proc_root.join("sys/kernel/osrelease"), "4.18.0-test\n").unwrap();

        let capability = KernelCapability::detect_from_roots(&proc_root, &sys_root, &boot_root);

        assert!(capability.bpf_lsm_active);
        assert!(capability.bpf_lsm_configured);
        assert!(capability.btf_vmlinux_available);

        let _ = fs::remove_dir_all(root);
    }

    fn make_temp_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "deepflow-kernel-capability-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }
}
