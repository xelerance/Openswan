# needsrootforbuild


Summary: Openswan IPSEC implementation
Name: openswan
Version: IPSECBASEVERSION
# Build KLIPS kernel module?
%{!?buildklips: %{expand: %%define buildklips 0}}
%{!?buildxen: %{expand: %%define buildxen 0}}

# The default kernel version to build for is the latest of
# the installed binary kernel
# This can be overridden by "--define 'kversion x.x.x-y.y.y'"
%define defkflavor %(uname -r | cut -d- -f 3)
%define defkrelease %(uname -r)
%define defkversion %(rpm -q --queryformat '%%{VERSION}-%%{RELEASE}' kernel-%{defkflavor})
%{!?kflavor: %{expand: %%define kflavor %defkflavor}}
%{!?krelease: %{expand: %%define krelease %defkrelease}}
%{!?kversion: %{expand: %%define kversion %defkversion}}
%define krelver %(echo %{krelease} | tr -s '-' '_')

# Openswan -pre/-rc nomenclature has to co-exist with hyphen paranoia
%define srcpkgver %(echo %{version} | tr -s '_' '-')
%define ourrelease 1
Release: %{ourrelease}
License: GPLv2
Url: http://www.openswan.org/
Source: openswan-%{srcpkgver}.tar.gz
Patch1: rc.patch
Patch2: kernelsrc.patch
Group: Productivity/Networking/Security
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Summary: Openswan - An IPsec and IKE implementation
PreReq: %insserv_prereq %fillup_prereq perl
BuildRequires: gmp-devel bison flex bind-devel xmlto sgml-skel
Requires: iproute2 >= 2.6.8
AutoReqProv:    on

Prefix:         /usr

%description
Openswan is a free implementation of IPSEC & IKE for Linux.  IPSEC is 
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and 
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Openswan on a freeswan enabled kernel. It optionally also builds the
Openswan KLIPS IPsec stack that is an alternative for the NETKEY/XFRM
IPsec stack that exists in the default Linux kernel.

%if %{buildklips}
%package klips
Summary: Openswan kernel module
Group:  System/Kernel
Release: %{krelver}_%{ourrelease}
Requires: kernel-%{kflavor} = %{kversion}
BuildRequires: kernel-%{kflavor} = %{kversion}, kernel-source = %{kversion}
%endif

%if %{buildklips}
%description klips
This package contains only the ipsec module for the RedHat/Fedora series of
kernels.
%endif

%prep
%setup -q -n openswan-%{srcpkgver}
%patch1 -p1
%patch2 -p1
sed -i 's/-Werror/#-Werror/' lib/libdns/Makefile
sed -i 's/-Werror/#-Werror/' lib/libisc/Makefile
sed -i 's/-Werror/#-Werror/' lib/liblwres/Makefile

%build
# Suse has no %{_libexecdir} directory, put it all in libdir instead (yuck)
%{__make} \
  USERCOMPILE='-g $(RPM_OPT_FLAGS) -DGCC_LINT' \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libdir}/ipsec \
  FINALBINDIR=%{_libdir}/ipsec \
  FINALLIBEXECDIR=%{_libdir}/ipsec \
  MANTREE=%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  INC_RCDIRS='/etc/init.d /etc/rc.d/init.d /etc/rc.d /sbin/init.d' \
  INC_DOCDIR=share/doc/packages \
  programs
FS=$(pwd)
%if %{buildklips}
mkdir -p BUILD.%{_target_cpu}

cd packaging/suse
# rpm doesn't know we're compiling kernel code. optflags will give us -m64
%{__make} -C $FS MOD26BUILDDIR=$FS/BUILD.%{_target_cpu} \
    OPENSWANSRCDIR=$FS \
    KLIPSCOMPILE="%{optflags}" \
    KERNELDIR=/lib/modules/%{krelease}/build \
%if %{buildxen}
    ARCH=xen \
%else
    ARCH=%{_arch} \
%endif
    include module
%endif

%install
%{__make} \
  DESTDIR=%{buildroot} \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libdir}/ipsec \
  FINALBINDIR=%{_libdir}/ipsec \
  FINALLIBEXECDIR=%{_libdir}/ipsec \
  MANTREE=%{buildroot}%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/openswan
rm -rf %{buildroot}/%{_initrddir}/setup
rm -rf %{buildroot}/etc/ipsec.d/examples
find %{buildroot}%{_mandir}  -type f | xargs chmod a-x
install -d -m 0700 %{buildroot}%{_localstatedir}/run/pluto
install -d %{buildroot}%{_sbindir}
#suse specific
ln -sf /etc/init.d/ipsec ${RPM_BUILD_ROOT}%{prefix}/sbin/rcipsec
#echo "# see man ipsec.secrets" >  $RPM_BUILD_ROOT/etc/ipsec.secrets
install -d -m 755 %{buildroot}/etc/sysconfig/network/{scripts,if-up.d,if-down.d}
install -m 755 packaging/suse/sysconfig.network.scripts.openswan %{buildroot}/etc/sysconfig/network/scripts/freeswan
install -m 644 packaging/suse/sysconfig.network.scripts.openswan-functions %{buildroot}/etc/sysconfig/network/scripts/freeswan-functions
ln -s ../scripts/freeswan %{buildroot}/etc/sysconfig/network/if-up.d/freeswan
ln -s ../scripts/freeswan %{buildroot}/etc/sysconfig/network/if-down.d/freeswan
# ip-up script (#39048)
install -d -m 750 -g dialout %{buildroot}/etc/ppp/ip-{up,down}.d
install -d -m 750 %{buildroot}/etc/ppp/ip-{up,down}.d
install -m 755 packaging/suse/openswan.ip-up %{buildroot}/etc/ppp/ip-up.d/freeswan
ln -s ../ip-up.d/freeswan %{buildroot}/etc/ppp/ip-down.d/freeswan
rm -f %{buildroot}/etc/rc?.d/[KS]*ipsec

%if %{buildklips}
mkdir -p %{buildroot}/lib/modules/%{krelease}/kernel/net/ipsec
for i in $FS/BUILD.%{_target_cpu}/ipsec.ko  $FS/modobj/ipsec.o
do
  if [ -f $i ]
  then
    cp $i %{buildroot}/lib/modules/%{krelease}/kernel/net/ipsec 
  fi
done
%endif

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
%dir %attr(700,root,root) /etc/ipsec.d/policies
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%{_localstatedir}/run/pluto
%{_initrddir}/ipsec
%{_libdir}/ipsec
%{_sbindir}/rcipsec
%{_sbindir}/ipsec
%doc %{_mandir}/*/*
/etc/sysconfig/network/scripts/*
/etc/sysconfig/network/if-up.d/freeswan
/etc/sysconfig/network/if-down.d/freeswan
/etc/ppp/ip-up.d/freeswan
/etc/ppp/ip-down.d/freeswan
%dir %attr(700,root,root) /etc/ipsec.d/private

%if %{buildklips}
%files klips
%defattr (-,root,root)
/lib/modules/%{krelease}/kernel/net/ipsec
%endif

%preun
%{stop_on_removal ipsec}
# Some people expect to not loose their secrets even after multiple rpm -e.
if test -s etc/ipsec.secrets.rpmsave; then
  cp -p --backup=numbered etc/ipsec.secrets.rpmsave etc/ipsec.secrets.rpmsave.old
fi
exit 0

%postun
%{restart_on_update ipsec}
%{insserv_cleanup}

%if %{buildklips}
%postun klips
/sbin/depmod -a -e -F /boot/System.map-%{krelease} %{krelease}
%post klips
/sbin/depmod -a -e -F /boot/System.map-%{krelease} %{krelease}
%endif

%post 
%{fillup_and_insserv ipsec}
# don't create host keys on install - might be no entropy!
# openswan automatically does it on 'start' if no ipsec.secrets is found

%changelog
* Wed May 07 2008 Paul Wouters <paul@xelerance.com> - 2.5.50-1
- Various spec file fixes to compile on SLES 10 SP1
- Suse has no libexec directory - use libdir

* Fri Apr 18 2008 Paul Wouters <paul@xelerance.com> - 2.5.49-1
- Incororated Suse initscripts and some SPEC semantics from mt@suse.de

* Thu Dec 20 2007 Paul Wouters <paul@xelerance.com> - 2.6.01-1
- Work around for warnings in BIND related code
- Remove bogus file /etc/init.d/setup at install
- Cleaned up spec file

* Mon Oct 10 2005 Paul Wouters <paul@xelerance.com>
- Updated for klips on xen 
- added ldconfig for post klips to obtain ipsec module dependancies
- Run 'make include' since on FC4 kernel source does not have the links yet.

* Wed Jan  5 2005 Paul Wouters <paul@xelerance.com>
- Updated for x86_64 and klips on 2.6

* Sun Sep  5 2004 Paul Wouters <paul@xelerance.com>
- Updated for openswan

* Fri Aug 22 2003 Sam Sgro <sam@freeswan.org>
- Juggling release/source package names to allow for 
  -pre/-rc releases to build.

* Thu Aug 14 2003 Sam Sgro <sam@freeswan.org>
- Reverting back to pre-x.509 version, cosmetic changes.

* Tue May 20 2003 Charlie Brady <charlieb@e-smith.com> 2.0.0-x509_1.3.2_2es
- Add "Obsoletes: freeswan" to userland RPM.

* Fri May 16 2003 Charlie Brady <charlieb@e-smith.com> 2.0.0-x509_1.3.2_1es
- Add version 1.3.2 of the x509 patch.
- Add missing /usr/libexec/ipsec dir and files.
- Minor tidy up of spec file.

* Thu May 15 2003 Charlie Brady <charlieb@e-smith.com> 2.0.0-1es
- Based on work by Paul Lahaie of Steamballoon, Michael
  Richardson of freeS/WAN team and Tuomo Soini <tis@foobar.fi>.
- Build freeswan RPMs from a single source RPM, for RedHat, but
  should work on any RPM based system.
