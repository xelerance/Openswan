Summary: Openswan IPSEC implementation
Name: openswan
Version: 2.CVSHEAD
# build kLIPS kerneo module or not
%{!?buildklips: %{expand: %%define buildklips 1}}

# annoyingly, one works on an fc3-amd, the other works on an fc3-intel.
# both have the same version of rom and coreutils ?
#%define defkv %(rpm -q --qf='%{Version}-%{Release}\ ' kernel | tr ' ' '\n' | tail -1)
%define defkv %(rpm -q --qf='%{Version}-%{Release}\\n' kernel|tail -1)
# The default kernel version to build for is the latest of
# the installed kernel-source RPMs.
# This can be overridden by "--define 'kversion x.x.x-y.y.y'"
%{!?kversion: %{expand: %%define kversion %defkv}}
%define	krelver		%(echo %{kversion} | tr -s '-' '_')
# Openswan -pre/-rc nomenclature has to co-exist with hyphen paranoia
%define srcpkgver	%(echo %{version} | tr -s '_' '-')
%define ourrelease 1
%define debug_package %{nil}
Release: %{ourrelease}
License: GPL
Url: http://www.openswan.org/
Source: openswan-%{srcpkgver}.tar.gz
Group: System Environment/Daemons
BuildRoot: /var/tmp/%{name}-%{PACKAGE_VERSION}-root
%define __spec_install_post /usr/lib/rpm/brp-compress || :
Provides: ipsec-userland

%package userland
Summary: Openswan IPSEC usermod tools
Group: System Environment/Daemons
Provides: ipsec-userland
Obsoletes: freeswan superfreeswan super-freeswan
Requires: ipsec-kernel, iproute >= 2.6.8, gmp
BuildRequires: gmp-devel bison flex
Release: %{ourrelease}

%package doc
Summary: Openswan IPSEC full documentation
Group: System Environment/Daemons
Release: %{ourrelease}

%if %{buildklips}
%package klips
Summary: Openswan kernel module
Group:  System Environment/Kernel
Release: %{krelver}_%{ourrelease}
Provides: ipsec-kernel
Requires: kernel = %{kversion}
# only applies to FC3+, not RH7-9 BuildRequires: kernel-devel
# do not make the dependancy circular for now.
#Requires: ipsec-userland
%endif

%description userland
Openswan is a free implementation of IPSEC & IKE for Linux.  IPSEC is 
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and 
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Openswan on a freeswan enabled kernel.

%if %{buildklips}
%description klips
This package contains only the ipsec module for the RedHat/Fedora series of
kernels.
%endif

%description doc
This package contains extensive documentation of the Openswan IPSEC
system.

%description
A dummy package that installs userland and kernel pieces.

%prep
rm -rf ${RPM_BUILD_ROOT}
%setup -q -n openswan-%{srcpkgver}

%build
%{__make} \
  USERCOMPILE="-g %{optflags}" \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libdir}/ipsec \
  MANTREE=%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  programs
FS=$(pwd)
%if %{buildklips}
mkdir -p BUILD.%{_target_cpu}
mkdir -p BUILD.%{_target_cpu}-smp

cd packaging/redhat
for smp in -smp ""
do
# rpm doesn't know we're compiling kernel code. optflags will give us -m64
%{__make} -C $FS MOD26BUILDDIR=$FS/BUILD.%{_target_cpu}$smp \
    OPENSWANSRCDIR=$FS \
    KLIPSCOMPILE="%{optflags}" \
    KERNELSRC=/lib/modules/%{kversion}/build \
    ARCH=%{_arch} \
    SUBARCH=%{_arch} \
    MODULE_DEF_INCLUDE=$FS/packaging/redhat/config-%{_target_cpu}$smp.h \
    NET_26_12_SKALLOC=1 \
    HAVE_SOCK_ZAPPED=1 \
    module
done
%endif

%install
%{__make} \
  DESTDIR=%{buildroot} \
  INC_USRLOCAL=%{_prefix} \
  FINALLIBDIR=%{_libdir}/ipsec \
  MANTREE=%{buildroot}%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/openswan
#this needs to be fixed in 'make install'
rm -rf %{buildroot}/etc/rc.d/rc?.d/*ipsec
install -d -m 0700 %{buildroot}%{_localstatedir}/run/pluto
install -d %{buildroot}%{_sbindir}

%if %{buildklips}
mkdir -p %{buildroot}/lib/modules/%{kversion}/kernel/net/ipsec
mkdir -p %{buildroot}/lib/modules/%{kversion}smp/kernel/net/ipsec
for i in $FS/BUILD.%{_target_cpu}/ipsec.ko  $FS/modobj/ipsec.o
do
  if [ -f $i ]
  then
    cp $i %{buildroot}/lib/modules/%{kversion}/kernel/net/ipsec 
  fi
done
for i in BUILD.%{_target_cpu}-smp/ipsec.o BUILD.%{_target_cpu}-smp/ipsec.ko  
do 
  if [ -f $i ]
  then
    cp $i  %{buildroot}/lib/modules/%{kversion}smp/kernel/net/ipsec
  fi
done
%endif

%clean
rm -rf ${RPM_BUILD_ROOT}

%files doc
%defattr(-,root,root)
%doc doc

#%files userland
%files 
%defattr(-,root,root)
%doc BUGS CHANGES COPYING CREDITS README LICENSE ROADMAP.txt
%doc doc/manpage.d/*
# /usr/share/doc/openswan/*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/examples/*
%{_localstatedir}/run/pluto
%config(noreplace) %{_initrddir}/ipsec
%{_libdir}/ipsec
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%doc %{_mandir}/*/*

%if %{buildklips}
%files klips
%defattr (-,root,root)
/lib/modules/%{kversion}/kernel/net/ipsec
/lib/modules/%{kversion}smp/kernel/net/ipsec
%endif

%pre 
%preun 
if [ $1 = 0 ]; then
    /sbin/service ipsec stop || :
    /sbin/chkconfig --del ipsec
fi

%postun userland
if [ $1 -ge 1 ] ; then
  /sbin/service ipsec stop 2>&1 > /dev/null && /sbin/service ipsec start  2>&1 > /dev/null || :
fi

%if %{buildklips}
%postun klips
%post klips
%endif

%post 
/sbin/chkconfig --add ipsec

%changelog
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
