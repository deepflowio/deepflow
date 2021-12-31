#[cfg(target_os = "linux")]
mod consts {

    pub const DEFAULT_LOGFILE: &'static str = "/var/log/trident/trident.log";
    pub const DEFAULT_CONF_FILE: &'static str = "/etc/trident.yaml";
    pub const COREFILE_FORMAT: &'static str = "core";
    pub const DEFAULT_COREFILE_PATH: &'static str = "/tmp";
    pub const DEFAULT_LIBVIRT_XML_PATH: &'static str = "/etc/libvirt/qemu";
}

#[cfg(target_os = "windows")]
mod consts {
    pub const DEFAULT_LOGFILE: &str = "C:\\DeepFlow\\trident\\log\\trident.log";
    // NOTE yaml must be full path, otherwise service wouldn't start as you wish.
    pub const DEFAULT_CONF_FILE: &str = "C:\\DeepFlow\\trident\\trident-windows.yaml";
    pub const DEFAULT_COREFILE_PATH: &str = "C:\\DeepFlow\\trident";
    pub const COREFILE_FORMAT: &str = "dump";
}
