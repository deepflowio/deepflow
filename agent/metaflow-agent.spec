Name:       metaflow-agent
Version:    1.0
Release:    %(git rev-list --count HEAD)%{?dist}
Summary:    deepflow metaflow agent

Group:      Applications/File
Vendor:     Yunshan Networks
License:    Copyright (c) 2012-2016 Yunshan Netwoks
URL:        http://yunshan.net
Source:     metaflow-agent.spec

BuildRequires: git
Requires(post): %{_sbindir}/update-alternatives
Requires(postun): %{_sbindir}/update-alternatives
Autoreq: 0

%define pwd %(echo $PWD)

%description
Deepflow MetaFlow Agent

%prep
mkdir -p $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/target/release/metaflow-agent $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/target/release/metaflow-agent-ctl $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/src/ebpf/metaflow-ebpfctl $RPM_BUILD_ROOT/usr/sbin/
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system/
cp %pwd/metaflow-agent.service $RPM_BUILD_ROOT/lib/systemd/system/
mkdir -p $RPM_BUILD_ROOT/etc/
cp %pwd/config/metaflow-agent.yaml $RPM_BUILD_ROOT/etc/
mkdir -p $RPM_BUILD_ROOT/usr/share/metaflow-agent/
cp -r %pwd/src/ebpf/data/* $RPM_BUILD_ROOT/usr/share/metaflow-agent/

%files
/usr/sbin/metaflow-agent
/lib/systemd/system/metaflow-agent.service
%config(noreplace) /etc/metaflow-agent.yaml
/usr/share/metaflow-agent/linux-5.2/socket_trace.elf
/usr/share/metaflow-agent/linux-common/socket_trace.elf
/usr/share/metaflow-agent/linux-core/socket_trace.elf

%preun
# sles: suse linux
if [ -n "`grep sles /etc/os-release`" ]; then
    if [ $1 == 0 ]; then # uninstall
        sed -i '/:\/usr\/sbin\/trident/d' /etc/inittab
        init q
    fi
else
    if [ $1 == 0 ]; then # uninstall
        systemctl stop metaflow-agent
        systemctl disable metaflow-agent
    fi
fi

%post
# sles: suse linux
if [ -n "`grep sles /etc/os-release`" ]; then
    if [ -n "`grep 'trid:' /etc/inittab`" ]; then
        echo 'inittab entry "trid" already exists!'
        exit 1
    fi
    sed -i '/:\/usr\/sbin\/metaflow\-agent/d' /etc/inittab
    echo 'trid:2345:respawn:/usr/sbin/metaflow-agent' >>/etc/inittab
    init q
else
    systemctl daemon-reload
    systemctl try-restart metaflow-agent
    [ -f /etc/metaflow-agent.yaml.sample ] || cp /etc/metaflow-agent.yaml{,.sample}
fi

%postun
# sles: suse linux
if [ -z "`grep sles /etc/os-release`" ]; then
    systemctl daemon-reload
fi

%changelog

%package -n %{name}-tools
Summary:    metaflow-agent tools

%description -n %{name}-tools
Deepflow MetaFlow Agent debug tools

%files -n %{name}-tools
/usr/sbin/metaflow-agent-ctl
/usr/sbin/metaflow-ebpfctl
