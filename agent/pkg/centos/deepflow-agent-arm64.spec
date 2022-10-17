Name:       deepflow-agent
Version:    1.0
Release:    %(git rev-list --count HEAD)%{?dist}
Summary:    deepflow agent

Group:      Applications/File
Vendor:     Yunshan Networks
License:    Copyright (c) 2012-2016 Yunshan Netwoks
URL:        http://yunshan.net
Source:     deepflow-agent.spec

Requires(post): %{_sbindir}/update-alternatives
Requires(postun): %{_sbindir}/update-alternatives
Autoreq: 0

%define pwd %(echo $PWD)

%description
Deepflow Agent

%prep
mkdir -p $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/output/target/aarch64-unknown-linux-musl/release/deepflow-agent $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/output/target/aarch64-unknown-linux-musl/release/deepflow-agent-ctl $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/output/src/ebpf/deepflow-ebpfctl $RPM_BUILD_ROOT/usr/sbin/
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system/
cp %pwd/pkg/deepflow-agent.service $RPM_BUILD_ROOT/lib/systemd/system/
mkdir -p $RPM_BUILD_ROOT/etc/
cp %pwd/config/deepflow-agent.yaml $RPM_BUILD_ROOT/etc/

%files
/usr/sbin/deepflow-agent
/lib/systemd/system/deepflow-agent.service
%config(noreplace) /etc/deepflow-agent.yaml

%preun
# sles: suse linux
if [ -n "`grep sles /etc/os-release`" ]; then
    if [ $1 == 0 ]; then # uninstall
        sed -i '/:\/usr\/sbin\/trident/d' /etc/inittab
        init q
    fi
else
    if [ $1 == 0 ]; then # uninstall
        systemctl stop deepflow-agent
        systemctl disable deepflow-agent
    fi
fi

%post
# sles: suse linux
if [ -n "`grep sles /etc/os-release`" ]; then
    if [ -n "`grep 'trid:' /etc/inittab`" ]; then
        echo 'inittab entry "trid" already exists!'
        exit 1
    fi
    sed -i '/:\/usr\/sbin\/deepflow\-agent/d' /etc/inittab
    echo 'trid:2345:respawn:/usr/sbin/deepflow-agent' >>/etc/inittab
    init q
else
    systemctl daemon-reload
    systemctl try-restart deepflow-agent
    [ -f /etc/deepflow-agent.yaml.sample ] || cp /etc/deepflow-agent.yaml{,.sample}
fi

%postun
# sles: suse linux
if [ -z "`grep sles /etc/os-release`" ]; then
    systemctl daemon-reload
fi

%changelog

%package -n %{name}-tools
Summary:    deepflow-agent tools

%description -n %{name}-tools
Deepflow Agent debug tools

%files -n %{name}-tools
/usr/sbin/deepflow-agent-ctl
/usr/sbin/deepflow-ebpfctl
