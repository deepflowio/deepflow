Name:       droplet
Version:    1.1
Release:    %(git rev-list --count HEAD)%{?dist}
Summary:    deepflow droplet

Group:      Applications/File
Vendor:     Yunshan Networks
License:    Copyright (c) 2012-2021 Yunshan Networks
URL:        http://yunshan.net
Source:     droplet.spec

BuildRequires: git
Requires: zeromq bash-completion
Requires(post): %{_sbindir}/update-alternatives
Requires(postun): %{_sbindir}/update-alternatives

%define pwd %(echo $PWD)

%description
deepflow droplet

%build
(cd %pwd; make clean && make)

%install
mkdir -p $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/bin/droplet $RPM_BUILD_ROOT/usr/sbin/
mkdir -p $RPM_BUILD_ROOT/usr/bin/
cp %pwd/bin/droplet-ctl $RPM_BUILD_ROOT/usr/bin/
go install github.com/go-delve/delve/cmd/dlv@latest
cp $(go env GOPATH)/bin/dlv $RPM_BUILD_ROOT/usr/bin/dlv.droplet
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system/
cp %pwd/droplet.service $RPM_BUILD_ROOT/lib/systemd/system/
mkdir -p $RPM_BUILD_ROOT/etc/
cp %pwd/droplet.yaml $RPM_BUILD_ROOT/etc/
cp %pwd/droplet.yaml $RPM_BUILD_ROOT/etc/droplet.yaml.sample
mkdir -p $RPM_BUILD_ROOT/usr/share/droplet/
mkdir -p $RPM_BUILD_ROOT%{pcapdir}

%files
/usr/bin/dlv.droplet
/usr/bin/droplet-ctl
/usr/sbin/droplet
/etc/droplet.yaml.sample
%config(noreplace) /lib/systemd/system/droplet.service
%config(noreplace) /etc/droplet.yaml

%preun
if [ $1 == 0 ]; then # uninstall
    systemctl stop droplet
    systemctl disable droplet
fi

%post
systemctl daemon-reload
systemctl try-restart droplet
%{_sbindir}/update-alternatives --install %{_bindir}/dlv dlv %{_bindir}/dlv.droplet 10

%postun
systemctl daemon-reload
if [ $1 == 0 ]; then # uninstall
    %{_sbindir}/update-alternatives --remove dlv %{_bindir}/dlv.droplet
fi

%changelog

