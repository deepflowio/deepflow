Name:       droplet
Version:    1.1
Release:    %(git rev-list --count HEAD)%{?dist}
Summary:    deepflow droplet

Group:      Applications/File
Vendor:     Yunshan Networks
License:    Copyright (c) 2012-2018 Yunshan Networks
URL:        http://yunshan.net
BuildArch:  x86_64
Source:     droplet.spec

BuildRequires: golang git
Requires: zeromq bash-completion
Requires(post): %{_sbindir}/update-alternatives
Requires(postun): %{_sbindir}/update-alternatives

%define pwd %(echo $PWD)
%define pcapdir /usr/local/deepflow/pcap-rest/

%description
deepflow droplet

%build
(cd %pwd; make clean && make)

%install
mkdir -p $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/bin/droplet $RPM_BUILD_ROOT/usr/sbin/
mkdir -p $RPM_BUILD_ROOT/usr/bin/
cp %pwd/bin/droplet-ctl $RPM_BUILD_ROOT/usr/bin/
go get github.com/derekparker/delve/cmd/dlv
cp $(go env GOPATH)/bin/dlv $RPM_BUILD_ROOT/usr/bin/dlv.droplet
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system/
cp %pwd/droplet.service $RPM_BUILD_ROOT/lib/systemd/system/
mkdir -p $RPM_BUILD_ROOT/etc/
cp %pwd/config/droplet.yaml $RPM_BUILD_ROOT/etc/
cp %pwd/config/droplet.yaml $RPM_BUILD_ROOT/etc/droplet.yaml.sample
mkdir -p $RPM_BUILD_ROOT/usr/share/droplet/
mkdir -p $RPM_BUILD_ROOT%{pcapdir}
cp %pwd/cmd/pcap-rest/*.py $RPM_BUILD_ROOT%{pcapdir}
cp %pwd/cmd/pcap-rest/requirements.txt $RPM_BUILD_ROOT%{pcapdir}
cp %pwd/pcap-rest.service $RPM_BUILD_ROOT/lib/systemd/system/

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
    systemctl stop pcap-rest
    systemctl disable pcap-test
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

%package -n pcap-rest
Summary:    deepflow pcap-rest

%description -n pcap-rest
deepflow pcap restful API agent

%files -n pcap-rest
%{pcapdir}/*.py*
%{pcapdir}/requirements.txt
%config(noreplace) /lib/systemd/system/pcap-rest.service

%post -n pcap-rest
[ -f %{pcapdir}/requirements.txt ] && python -m pip install -r %{pcapdir}/requirements.txt
systemctl daemon-reload
systemctl try-restart pcap-rest

%preun -n pcap-rest
if [ $1 == 0 ]; then # uninstall
    systemctl stop pcap-rest
    systemctl disable pcap-test
fi

%postun -n pcap-rest
systemctl daemon-reload
