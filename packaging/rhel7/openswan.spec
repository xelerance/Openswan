Summary: Openswan IPsec implementation
Name: openswanX
Version: 2.6.48dev

# Openswan -pre/-rc nomenclature has to co-exist with hyphen paranoia
%define srcpkgver %(echo %{version} | tr -s '_' '-')
%define ourrelease 2
Release: %{ourrelease}
License: GPLv2, some BSD
Url: http://www.openswan.org/
Source: openswan-%{srcpkgver}.tar.gz
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Summary: Openswan - An IPsec and IKE implementation
Group: System Environment/Daemons
# elinks is there to make xmlto happy on RHEL6.
BuildRequires: gmp-devel bison flex redhat-rpm-config xmlto elinks nss-devel nspr-devel
Conflicts: libreswan
Obsoletes: openswan

Requires: iproute >= 2.6.8

Requires(post): coreutils bash
Requires(preun): initscripts chkconfig
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service

%description
Openswan is a free implementation of IPsec & IKE for Linux.  IPsec is
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Openswan.  Openswan 2.6.x supports IKEv1 and IKEv2 (RFC4309,RFC5996,RFC7296)

%prep
%setup -q -n openswan-%{srcpkgver}

%build
%{__make} \
  USERCOMPILE="-g %{optflags} -fPIE -pie" \
  USERLINK="-g -pie" \
  USE_LIBNSS="true" \
  HAVE_THREADS="true" \
  USE_DYNAMICDNS="true" \
  WERROR="" \
  VENDOR="Xelerance" \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libdir}/ipsec \
  MANTREE=%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  programs
FS=$(pwd)

%install
rm -rf ${RPM_BUILD_ROOT}
%{__make} \
  DESTDIR=%{buildroot} \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libdir}/ipsec \
  MANTREE=%{buildroot}%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  WERROR="" \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/openswan
rm -rf %{buildroot}/%{_initrddir}/setup
rm -rf %{buildroot}/etc/ipsec.d/examples
find %{buildroot}%{_mandir}  -type f | xargs chmod a-x

install -d -m 0700 %{buildroot}%{_localstatedir}/run/pluto
# used when setting --perpeerlog without --perpeerlogbase
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root)
%doc BUGS CHANGES COPYING CREDITS README LICENSE
%doc OBJ.linux.*/programs/examples/*.conf
#%doc doc/manpage.d/*
# /usr/share/doc/openswan/*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto/peer
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%{_localstatedir}/run/pluto
%{_initrddir}/ipsec
%{_libdir}/ipsec
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%doc %{_mandir}/*/*

%preun
if [ $1 -eq 0 ]; then
        /sbin/service ipsec stop > /dev/null 2>&1
        /sbin/chkconfig --del ipsec
fi

%postun
if [ $1 -ge 1 ] ; then
 /sbin/service ipsec condrestart 2>&1 >/dev/null
fi

%post
/sbin/chkconfig --add ipsec

%changelog
* Mon Mar 02 2015 Michael Richardson <mcr@xelerance.com> - 2.6.44
  Renamed package to openswanX to deal with conflicts and obsolete statements.

