Name:       droplet
Version:    1.0
Release:    %(git rev-list --count HEAD)%{?dist}
Summary:    deepflow droplet

Group:      Applications/File
Vendor:     Yunshan Networks
License:    Copyright (c) 2012-2016 Yunshan Netwoks
URL:        http://yunshan.net
BuildArch:  x86_64
Source:     droplet.spec

BuildRequires: golang git

%define pwd %(echo $PWD)

%description
deepflow droplet

%prep
(cd %pwd; make clean && make)
mkdir -p $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/bin/droplet $RPM_BUILD_ROOT/usr/sbin/
mkdir -p $RPM_BUILD_ROOT/usr/bin/
cp $(go env GOPATH)/bin/dlv $RPM_BUILD_ROOT/usr/bin/
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system/
cp %pwd/droplet.service $RPM_BUILD_ROOT/lib/systemd/system/
mkdir -p $RPM_BUILD_ROOT/etc/
cp %pwd/config/droplet.yaml $RPM_BUILD_ROOT/etc/

%files
/usr/bin/dlv
/usr/sbin/droplet
/lib/systemd/system/droplet.service
%config(noreplace) /etc/droplet.yaml

%preun
if [ $1 == 0 ]; then # uninstall
    systemctl stop droplet
    systemctl disable droplet
fi

%post
systemctl daemon-reload
systemctl try-restart droplet

%postun
systemctl daemon-reload

%changelog
