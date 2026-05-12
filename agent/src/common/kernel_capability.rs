use std::{
    fs,
    io::{Cursor, Read},
    path::Path,
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
        let lsm_text = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
        let config_text = read_kernel_config().unwrap_or_default();

        Self {
            bpf_lsm_configured: config_enabled(&config_text, "CONFIG_BPF_LSM"),
            bpf_lsm_active: lsm_has_bpf(&lsm_text),
            bpf_kprobe_override_configured: config_enabled(
                &config_text,
                "CONFIG_BPF_KPROBE_OVERRIDE",
            ),
            seccomp_filter_configured: config_enabled(&config_text, "CONFIG_SECCOMP_FILTER"),
            btf_vmlinux_available: Path::new("/sys/kernel/btf/vmlinux").exists(),
        }
    }

    pub fn supports_exec_lsm_enforcement(&self) -> bool {
        self.bpf_lsm_configured && self.bpf_lsm_active
    }
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
    if let Some(config) = read_boot_kernel_config() {
        return Some(config);
    }
    read_proc_kernel_config()
}

fn read_boot_kernel_config() -> Option<String> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let path = format!("/boot/config-{}", release.trim());
    fs::read_to_string(path).ok()
}

fn read_proc_kernel_config() -> Option<String> {
    let compressed = fs::read("/proc/config.gz").ok()?;
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
}
