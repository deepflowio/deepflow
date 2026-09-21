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
    pub bpf_kprobe_override_available: bool,
    pub bpf_kprobe_override_symbols: Vec<String>,
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
        let bpf_kprobe_override_symbols = read_kprobe_override_symbols(sys_root);
        let bpf_kprobe_override_configured =
            config_enabled(&config_text, "CONFIG_BPF_KPROBE_OVERRIDE")
                || !bpf_kprobe_override_symbols.is_empty();

        Self {
            bpf_lsm_configured: config_enabled(&config_text, "CONFIG_BPF_LSM") || bpf_lsm_active,
            bpf_lsm_active,
            bpf_kprobe_override_configured,
            bpf_kprobe_override_available: bpf_kprobe_override_configured
                && !bpf_kprobe_override_symbols.is_empty(),
            bpf_kprobe_override_symbols,
            seccomp_filter_configured: config_enabled(&config_text, "CONFIG_SECCOMP_FILTER"),
            btf_vmlinux_available: sys_root.join("kernel/btf/vmlinux").exists(),
        }
    }

    pub fn supports_exec_lsm_enforcement(&self) -> bool {
        self.bpf_lsm_configured && self.bpf_lsm_active
    }

    pub fn supports_kprobe_override_symbol(&self, symbol: &str) -> bool {
        self.bpf_kprobe_override_available
            && self
                .bpf_kprobe_override_symbols
                .iter()
                .any(|allowed| allowed == symbol)
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

fn read_kprobe_override_symbols(sys_root: &Path) -> Vec<String> {
    const REL_PATHS: [&str; 2] = [
        "kernel/debug/error_injection/list",
        "kernel/debug/fail_function/injectable",
    ];

    let mut symbols = Vec::new();
    for rel_path in REL_PATHS {
        let Ok(text) = fs::read_to_string(sys_root.join(rel_path)) else {
            continue;
        };
        symbols.extend(parse_error_injection_symbols(&text));
    }
    symbols.sort();
    symbols.dedup();
    symbols
}

fn parse_error_injection_symbols(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let token = line.split_whitespace().next().unwrap_or_default().trim();
            if token.is_empty() || token.starts_with('#') {
                None
            } else {
                Some(token.to_string())
            }
        })
        .collect()
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
    fn parse_error_injection_list_takes_first_column() {
        assert_eq!(
            parse_error_injection_symbols("__x64_sys_reboot\tEI_ETYPE_ERRNO\n# ignored\n"),
            vec!["__x64_sys_reboot".to_string()]
        );
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

    #[test]
    fn detect_from_roots_uses_error_injection_allowlist_for_kprobe_override() {
        let root = make_temp_root("kprobe-override-allowlist");
        let proc_root = root.join("host-proc");
        let sys_root = root.join("host-sys");
        let boot_root = root.join("boot");
        fs::create_dir_all(proc_root.join("sys/kernel")).unwrap();
        fs::create_dir_all(sys_root.join("kernel/debug/error_injection")).unwrap();
        fs::write(proc_root.join("sys/kernel/osrelease"), "4.18.0-test\n").unwrap();
        fs::write(
            sys_root.join("kernel/debug/error_injection/list"),
            "__x64_sys_reboot\n__x64_sys_init_module\n",
        )
        .unwrap();

        let capability = KernelCapability::detect_from_roots(&proc_root, &sys_root, &boot_root);

        assert!(capability.bpf_kprobe_override_configured);
        assert!(capability.bpf_kprobe_override_available);
        assert!(capability.supports_kprobe_override_symbol("__x64_sys_reboot"));
        assert!(!capability.supports_kprobe_override_symbol("__x64_sys_mount"));

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
