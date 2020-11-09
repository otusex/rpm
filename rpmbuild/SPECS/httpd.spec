%define contentdir %{_datadir}/httpd
%define docroot /var/www
%define suexec_caller apache
%define mmn 20120211
%define oldmmnisa %{mmn}-%{__isa_name}-%{__isa_bits}
%define mmnisa %{mmn}%{__isa_name}%{__isa_bits}
%define vstring CentOS

# Drop automatic provides for module DSOs
%{?filter_setup:
%filter_provides_in %{_libdir}/httpd/modules/.*\.so$
%filter_setup
}
# 
Summary: Apache HTTP Server
Name: httpd
Version: 2.4.6
Release: 93%{?dist}
URL: http://httpd.apache.org/
Source0: http://www.apache.org/dist/httpd/httpd-%{version}.tar.bz2
Source1: centos-noindex.tar.gz
Source2: httpd.logrotate
Source3: httpd.sysconf
Source4: httpd-ssl-pass-dialog
Source5: httpd.tmpfiles
Source6: httpd.service
Source7: action-graceful.sh
Source8: action-configtest.sh
Source10: httpd.conf
Source11: 00-base.conf
Source12: 00-mpm.conf
Source13: 00-lua.conf
Source14: 01-cgi.conf
Source15: 00-dav.conf
Source16: 00-proxy.conf
Source17: 00-ssl.conf
Source18: 01-ldap.conf
Source19: 00-proxyhtml.conf
Source20: userdir.conf
Source21: ssl.conf
Source22: welcome.conf
Source23: manual.conf
Source24: 00-systemd.conf
Source25: 01-session.conf
# Documentation
Source30: README.confd
Source40: htcacheclean.service
Source41: htcacheclean.sysconf
# build/scripts patches
Patch1: httpd-2.4.1-apctl.patch
Patch2: httpd-2.4.3-apxs.patch
Patch3: httpd-2.4.1-deplibs.patch
Patch5: httpd-2.4.3-layout.patch
Patch6: httpd-2.4.3-apctl-systemd.patch
# Features/functional changes
Patch21: httpd-2.4.6-full-release.patch
Patch23: httpd-2.4.4-export.patch
Patch24: httpd-2.4.1-corelimit.patch
Patch25: httpd-2.4.1-selinux.patch
Patch26: httpd-2.4.4-r1337344+.patch
Patch27: httpd-2.4.2-icons.patch
Patch28: httpd-2.4.6-r1332643+.patch
Patch29: httpd-2.4.3-mod_systemd.patch
Patch30: httpd-2.4.4-cachehardmax.patch
Patch31: httpd-2.4.6-sslmultiproxy.patch
Patch32: httpd-2.4.6-r1537535.patch
Patch33: httpd-2.4.6-r1542327.patch
Patch34: httpd-2.4.6-ssl-large-keys.patch
Patch35: httpd-2.4.6-pre_htaccess.patch
Patch36: httpd-2.4.6-r1573626.patch
Patch37: httpd-2.4.6-uds.patch
Patch38: httpd-2.4.6-upn.patch
Patch39: httpd-2.4.6-r1664565.patch
Patch40: httpd-2.4.6-r1861793+.patch
# Bug fixes
Patch51: httpd-2.4.3-sslsninotreq.patch
Patch55: httpd-2.4.4-malformed-host.patch
Patch56: httpd-2.4.4-mod_unique_id.patch
Patch57: httpd-2.4.6-ldaprefer.patch
Patch58: httpd-2.4.6-r1507681+.patch
Patch59: httpd-2.4.6-r1556473.patch
Patch60: httpd-2.4.6-r1553540.patch
Patch61: httpd-2.4.6-rewrite-clientaddr.patch
Patch62: httpd-2.4.6-ab-overflow.patch
Patch63: httpd-2.4.6-sigint.patch
Patch64: httpd-2.4.6-ssl-ecdh-auto.patch
Patch65: httpd-2.4.6-r1556818.patch
Patch66: httpd-2.4.6-r1618851.patch
Patch67: httpd-2.4.6-r1526189.patch
Patch68: httpd-2.4.6-r1663647.patch
Patch69: httpd-2.4.6-r1569006.patch
Patch70: httpd-2.4.6-r1506474.patch
Patch71: httpd-2.4.6-bomb.patch
Patch72: httpd-2.4.6-r1604460.patch
Patch73: httpd-2.4.6-r1624349.patch
Patch74: httpd-2.4.6-ap-ipv6.patch
Patch75: httpd-2.4.6-r1530280.patch
Patch76: httpd-2.4.6-r1633085.patch
Patch78: httpd-2.4.6-ssl-error-free.patch
Patch79: httpd-2.4.6-r1528556.patch
Patch80: httpd-2.4.6-r1594625.patch
Patch81: httpd-2.4.6-r1674222.patch
Patch82: httpd-2.4.6-apachectl-httpd-env.patch
Patch83: httpd-2.4.6-rewrite-dir.patch
Patch84: httpd-2.4.6-r1420184.patch
Patch85: httpd-2.4.6-r1524368.patch
Patch86: httpd-2.4.6-r1528958.patch
Patch87: httpd-2.4.6-r1651083.patch
Patch88: httpd-2.4.6-r1688399.patch
Patch89: httpd-2.4.6-r1527509.patch
Patch90: httpd-2.4.6-apachectl-status.patch
Patch91: httpd-2.4.6-r1650655.patch
Patch92: httpd-2.4.6-r1533448.patch
Patch93: httpd-2.4.6-r1610013.patch
Patch94: httpd-2.4.6-r1705528.patch
Patch95: httpd-2.4.6-r1684462.patch
Patch96: httpd-2.4.6-r1650677.patch
Patch97: httpd-2.4.6-r1621601.patch
Patch98: httpd-2.4.6-r1610396.patch
Patch99: httpd-2.4.6-rotatelog-timezone.patch
Patch100: httpd-2.4.6-ab-ssl-error.patch
Patch101: httpd-2.4.6-r1723522.patch
Patch102: httpd-2.4.6-r1681107.patch
Patch103: httpd-2.4.6-dhparams-free.patch
Patch104: httpd-2.4.6-r1651658.patch
Patch105: httpd-2.4.6-r1560093.patch
Patch106: httpd-2.4.6-r1748212.patch
Patch107: httpd-2.4.6-r1570327.patch
Patch108: httpd-2.4.6-r1631119.patch
Patch109: httpd-2.4.6-r1593002.patch
Patch110: httpd-2.4.6-r1662640.patch
Patch111: httpd-2.4.6-r1348019.patch
Patch112: httpd-2.4.6-r1587053.patch
Patch113: httpd-2.4.6-mpm-segfault.patch
Patch114: httpd-2.4.6-r1681114.patch
Patch115: httpd-2.4.6-r1775832.patch
Patch116: httpd-2.4.6-r1726019.patch
Patch117: httpd-2.4.6-r1683112.patch
Patch118: httpd-2.4.6-r1651653.patch
Patch119: httpd-2.4.6-r1634529.patch
Patch120: httpd-2.4.6-r1738878.patch
Patch121: httpd-2.4.6-http-protocol-options-define.patch
Patch122: httpd-2.4.6-statements-comment.patch
Patch123: httpd-2.4.6-rotatelogs-zombie.patch
Patch124: httpd-2.4.6-mod_authz_dbd-missing-query.patch
Patch125: httpd-2.4.6-r1668532.patch
Patch126: httpd-2.4.6-r1681289.patch
Patch127: httpd-2.4.6-r1805099.patch
Patch128: httpd-2.4.6-r1811831.patch
Patch129: httpd-2.4.6-r1811746.patch
Patch130: httpd-2.4.6-r1811976.patch
Patch131: httpd-2.4.6-r1650310.patch
Patch132: httpd-2.4.6-r1530999.patch
Patch133: httpd-2.4.6-r1555539.patch
Patch134: httpd-2.4.6-r1737363.patch
Patch135: httpd-2.4.6-r1826995.patch
Patch136: httpd-2.4.6-default-port-worker.patch
Patch137: httpd-2.4.6-r1825120.patch
Patch138: httpd-2.4.6-r1515372.patch
Patch139: httpd-2.4.6-r1824872.patch
Patch140: httpd-2.4.6-r1833014.patch
Patch141: httpd-2.4.6-r1583175.patch
Patch142: httpd-2.4.6-r1862604.patch

# Security fixes
Patch200: httpd-2.4.6-CVE-2013-6438.patch
Patch201: httpd-2.4.6-CVE-2014-0098.patch
Patch202: httpd-2.4.6-CVE-2014-0231.patch
Patch203: httpd-2.4.6-CVE-2014-0117.patch
Patch204: httpd-2.4.6-CVE-2014-0118.patch
Patch205: httpd-2.4.6-CVE-2014-0226.patch
Patch206: httpd-2.4.6-CVE-2013-4352.patch
Patch207: httpd-2.4.6-CVE-2013-5704.patch
Patch208: httpd-2.4.6-CVE-2014-3581.patch
Patch209: httpd-2.4.6-CVE-2015-3185.patch
Patch210: httpd-2.4.6-CVE-2015-3183.patch
Patch211: httpd-2.4.6-CVE-2016-5387.patch
Patch212: httpd-2.4.6-CVE-2016-8743.patch
Patch213: httpd-2.4.6-CVE-2016-0736.patch
Patch214: httpd-2.4.6-CVE-2016-2161.patch
Patch215: httpd-2.4.6-CVE-2017-3167.patch
Patch216: httpd-2.4.6-CVE-2017-3169.patch
Patch217: httpd-2.4.6-CVE-2017-7668.patch
Patch218: httpd-2.4.6-CVE-2017-7679.patch
Patch219: httpd-2.4.6-CVE-2017-9788.patch
Patch220: httpd-2.4.6-CVE-2017-9798.patch
Patch221: httpd-2.4.6-CVE-2018-1312.patch
Patch222: httpd-2.4.6-CVE-2019-0217.patch
Patch223: httpd-2.4.6-CVE-2019-0220.patch
Patch224: httpd-2.4.6-CVE-2017-15710.patch
Patch225: httpd-2.4.6-CVE-2018-1301.patch
Patch226: httpd-2.4.6-CVE-2018-17199.patch

License: ASL 2.0
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: autoconf, perl, pkgconfig, findutils, xmlto
BuildRequires: zlib-devel, libselinux-devel, lua-devel
BuildRequires: apr-devel >= 1.4.0, apr-util-devel >= 1.2.0, pcre-devel >= 5.0
BuildRequires: systemd-devel
Requires: /etc/mime.types, system-logos >= 7.92.1-1
Obsoletes: httpd-suexec
Provides: webserver
Provides: mod_dav = %{version}-%{release}, httpd-suexec = %{version}-%{release}
Provides: httpd-mmn = %{mmn}, httpd-mmn = %{mmnisa}, httpd-mmn = %{oldmmnisa}
Requires: httpd-tools = %{version}-%{release}
Requires(pre): /usr/sbin/useradd
Requires(pre): /usr/sbin/groupadd
Requires(preun): systemd-units
Requires(postun): systemd-units
Requires(post): systemd-units

%description
The Apache HTTP Server 

%package devel
Group: Development/Libraries
Summary: Development interfaces for the Apache HTTP server
Obsoletes: secureweb-devel, apache-devel, stronghold-apache-devel
Requires: apr-devel, apr-util-devel, pkgconfig
Requires: httpd = %{version}-%{release}

%description devel
The httpd-devel package contains the APXS binary and other files
that you need to build Dynamic Shared Objects (DSOs) for the
Apache HTTP Server.


%package manual
Group: Documentation
Summary: Documentation for the Apache HTTP server
Requires: httpd = %{version}-%{release}
Obsoletes: secureweb-manual, apache-manual
BuildArch: noarch

%description manual
The httpd-manual package contains the complete manual 

%package tools
Group: System Environment/Daemons
Summary: Tools for use with the Apache HTTP Server

%description tools
The httpd-tools package contains tools which can be used with 
the Apache HTTP Server.

%package -n mod_ssl
Group: System Environment/Daemons
Summary: SSL/TLS module for the Apache HTTP Server
Epoch: 1
BuildRequires: openssl-devel >= 1:1.0.1e-37
Requires: openssl-libs >= 1:1.0.1e-37
Requires(post): openssl, /bin/cat, hostname
Requires(pre): httpd
Requires: httpd = 0:%{version}-%{release}, httpd-mmn = %{mmnisa}
Obsoletes: stronghold-mod_ssl

%description -n mod_ssl
Security (TLS) protocols.

%package -n mod_proxy_html
Group: System Environment/Daemons
Summary: HTML and XML content filters for the Apache HTTP Server
Requires: httpd = 0:%{version}-%{release}, httpd-mmn = %{mmnisa}
BuildRequires: libxml2-devel
Epoch: 1
Obsoletes: mod_proxy_html < 1:2.4.1-2

%description -n mod_proxy_html
The mod_proxy_html and mod_xml2enc modules provide filters which can
transform and modify HTML and XML content.

%package -n mod_ldap
Group: System Environment/Daemons
Summary: LDAP authentication modules for the Apache HTTP Server
Requires: httpd = 0:%{version}-%{release}, httpd-mmn = %{mmnisa}
Requires: apr-util-ldap

%description -n mod_ldap
The mod_ldap and mod_authnz_ldap modules add support for LDAP
authentication to the Apache HTTP Server.

%package -n mod_session
Group: System Environment/Daemons
Summary: Session interface for the Apache HTTP Server
Requires: httpd = 0:%{version}-%{release}, httpd-mmn = %{mmnisa}
Requires: apr-util-openssl

%description -n mod_session
The mod_session module and associated backends provide an abstract
interface for storing and accessing per-user session data.

%prep
%setup -q
%patch1 -p1 -b .apctl
%patch2 -p1 -b .apxs
%patch3 -p1 -b .deplibs
%patch5 -p1 -b .layout
%patch6 -p1 -b .apctlsystemd

%patch21 -p1 -b .fullrelease
%patch23 -p1 -b .export
%patch24 -p1 -b .corelimit
%patch25 -p1 -b .selinux
%patch26 -p1 -b .r1337344+
%patch27 -p1 -b .icons
%patch28 -p1 -b .r1332643+
%patch29 -p1 -b .systemd
%patch30 -p1 -b .cachehardmax
%patch31 -p1 -b .sslmultiproxy
%patch32 -p1 -b .r1537535
%patch33 -p1 -b .r1542327
rm modules/ssl/ssl_engine_dh.c
%patch34 -p1 -b .ssllargekeys
%patch35 -p1 -b .prehtaccess
%patch36 -p1 -b .r1573626
%patch37 -p1 -b .uds
%patch38 -p1 -b .upn
%patch39 -p1 -b .r1664565
%patch40 -p1 -b .r1861793+

%patch51 -p1 -b .sninotreq
%patch55 -p1 -b .malformedhost
%patch56 -p1 -b .uniqueid
%patch57 -p1 -b .ldaprefer
%patch58 -p1 -b .r1507681+
%patch59 -p1 -b .r1556473
%patch60 -p1 -b .r1553540
%patch61 -p1 -b .clientaddr
%patch62 -p1 -b .aboverflow
%patch63 -p1 -b .sigint
%patch64 -p1 -b .sslecdhauto
%patch65 -p1 -b .r1556818
%patch66 -p1 -b .r1618851
%patch67 -p1 -b .r1526189
%patch68 -p1 -b .r1663647
%patch69 -p1 -b .1569006
%patch70 -p1 -b .r1506474
%patch71 -p1 -b .bomb
%patch72 -p1 -b .r1604460
%patch73 -p1 -b .r1624349
%patch74 -p1 -b .abipv6
%patch75 -p1 -b .r1530280
%patch76 -p1 -b .r1633085
%patch78 -p1 -b .sslerrorfree
%patch79 -p1 -b .r1528556
%patch80 -p1 -b .r1594625
%patch81 -p1 -b .r1674222
%patch82 -p1 -b .envhttpd
%patch83 -p1 -b .rewritedir
%patch84 -p1 -b .r1420184
%patch85 -p1 -b .r1524368
%patch86 -p1 -b .r1528958
%patch87 -p1 -b .r1651083
%patch88 -p1 -b .r1688399
%patch89 -p1 -b .r1527509
%patch90 -p1 -b .apachectlstatus
%patch91 -p1 -b .r1650655
%patch92 -p1 -b .r1533448
%patch93 -p1 -b .r1610013
%patch94 -p1 -b .r1705528
%patch95 -p1 -b .r1684462
%patch96 -p1 -b .r1650677
%patch97 -p1 -b .r1621601
%patch98 -p1 -b .r1610396
%patch99 -p1 -b .rotatelogtimezone
%patch100 -p1 -b .absslerror
%patch101 -p1 -b .r1723522
%patch102 -p1 -b .r1681107
%patch103 -p1 -b .dhparamsfree
%patch104 -p1 -b .r1651658
%patch105 -p1 -b .r1560093
%patch106 -p1 -b .r1748212
%patch107 -p1 -b .r1570327
%patch108 -p1 -b .r1631119
%patch109 -p1 -b .r1593002
%patch110 -p1 -b .r1662640
%patch111 -p1 -b .r1348019
%patch112 -p1 -b .r1587053
%patch113 -p1 -b .mpmsegfault
%patch114 -p1 -b .r1681114
%patch115 -p1 -b .r1371876
%patch116 -p1 -b .r1726019
%patch117 -p1 -b .r1683112
%patch118 -p1 -b .r1651653
%patch119 -p1 -b .r1634529
%patch120 -p1 -b .r1738878
%patch121 -p1 -b .httpprotdefine
%patch122 -p1 -b .statement-comment
%patch123 -p1 -b .logrotate-zombie
%patch124 -p1 -b .modauthzdbd-segfault
%patch125 -p1 -b .r1668532
%patch126 -p1 -b .r1681289
%patch127 -p1 -b .r1805099
%patch128 -p1 -b .r1811831
%patch129 -p1 -b .r1811746
%patch130 -p1 -b .r1811976
%patch131 -p1 -b .r1650310
%patch132 -p1 -b .r1530999
%patch133 -p1 -b .r1555539
%patch134 -p1 -b .r1523536
%patch135 -p1 -b .r1826995
%patch136 -p1 -b .defaultport-proxy
%patch137 -p1 -b .r1825120
%patch138 -p1 -b .r1515372
%patch139 -p1 -b .r1824872
%patch140 -p1 -b .r1833014
%patch141 -p1 -b .r1583175
%patch142 -p1 -b .1862604


%patch200 -p1 -b .cve6438
%patch201 -p1 -b .cve0098
%patch202 -p1 -b .cve0231
%patch203 -p1 -b .cve0117
%patch204 -p1 -b .cve0118
%patch205 -p1 -b .cve0226
%patch206 -p1 -b .cve4352
%patch207 -p1 -b .cve5704
%patch208 -p1 -b .cve3581
%patch209 -p1 -b .cve3185
%patch210 -p1 -b .cve3183
%patch211 -p1 -b .cve5387
%patch212 -p1 -b .cve8743
%patch213 -p1 -b .cve0736
%patch214 -p1 -b .cve2161
%patch215 -p1 -b .cve3167
%patch216 -p1 -b .cve3169
%patch217 -p1 -b .cve7668
%patch218 -p1 -b .cve7679
%patch219 -p1 -b .cve9788
%patch220 -p1 -b .cve9798
%patch221 -p1 -b .cve1312
%patch222 -p1 -b .cve0217
%patch223 -p1 -b .cve0220
%patch224 -p1 -b .cve15710
%patch225 -p1 -b .cve1301
%patch226 -p1 -b .cve17199

# Patch in the vendor string and the release string
sed -i '/^#define PLATFORM/s/Unix/%{vstring}/' os/unix/os.h
sed -i 's/@RELEASE@/%{release}/' server/core.c

# Prevent use of setcap in "install-suexec-caps" target.
sed -i '/suexec/s,setcap ,echo Skipping setcap for ,' Makefile.in

# Safety check: prevent build if defined MMN does not equal upstream MMN.
vmmn=`echo MODULE_MAGIC_NUMBER_MAJOR | cpp -include include/ap_mmn.h | sed -n '/^2/p'`
if test "x${vmmn}" != "x%{mmn}"; then
   : Error: Upstream MMN is now ${vmmn}, packaged MMN is %{mmn}
   : Update the mmn macro and rebuild.
   exit 1
fi

: Building with MMN %{mmn}, MMN-ISA %{mmnisa} and vendor string '%{vstring}'

%build
# forcibly prevent use of bundled apr, apr-util, pcre
rm -rf srclib/{apr,apr-util,pcre}

# regenerate configure scripts
autoheader && autoconf || exit 1

# Before configure; fix location of build dir in generated apxs
%{__perl} -pi -e "s:\@exp_installbuilddir\@:%{_libdir}/httpd/build:g" \
	support/apxs.in

export CFLAGS=$RPM_OPT_FLAGS
export LDFLAGS="-Wl,-z,relro,-z,now"

%ifarch ppc64 ppc64le
%global _performance_build 1
%endif

# Hard-code path to links to avoid unnecessary builddep
export LYNX_PATH=/usr/bin/links

# Build the daemon
%configure \
 	--prefix=%{_sysconfdir}/httpd \
 	--exec-prefix=%{_prefix} \
 	--bindir=%{_bindir} \
 	--sbindir=%{_sbindir} \
 	--mandir=%{_mandir} \
	--libdir=%{_libdir} \
	--sysconfdir=%{_sysconfdir}/httpd/conf \
	--includedir=%{_includedir}/httpd \
	--libexecdir=%{_libdir}/httpd/modules \
	--datadir=%{contentdir} \
        --enable-layout=Fedora \
        --with-installbuilddir=%{_libdir}/httpd/build \
        --enable-mpms-shared=all \
        --with-apr=%{_prefix} --with-apr-util=%{_prefix} \
	--enable-suexec --with-suexec \
        --enable-suexec-capabilities \
	--with-suexec-caller=%{suexec_caller} \
	--with-suexec-docroot=%{docroot} \
	--without-suexec-logfile \
        --with-suexec-syslog \
	--with-suexec-bin=%{_sbindir}/suexec \
	--with-suexec-uidmin=500 --with-suexec-gidmin=100 \
        --enable-pie \
        --with-pcre \
        --enable-mods-shared=all \
	--enable-ssl --with-ssl --disable-distcache \
	--enable-proxy \
        --enable-cache \
        --enable-disk-cache \
        --enable-ldap --enable-authnz-ldap \
        --enable-cgid --enable-cgi \
        --enable-authn-anon --enable-authn-alias \
        --disable-imagemap  \
	$*
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT install

# Install systemd service files
mkdir -p $RPM_BUILD_ROOT%{_unitdir}
for s in httpd htcacheclean; do
  install -p -m 644 $RPM_SOURCE_DIR/${s}.service \
                    $RPM_BUILD_ROOT%{_unitdir}/${s}.service
done

# install conf file/directory
mkdir $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d \
      $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.modules.d
install -m 644 $RPM_SOURCE_DIR/README.confd \
    $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/README
for f in 00-base.conf 00-mpm.conf 00-lua.conf 01-cgi.conf 00-dav.conf \
         00-proxy.conf 00-ssl.conf 01-ldap.conf 00-proxyhtml.conf \
         01-ldap.conf 00-systemd.conf 01-session.conf; do
  install -m 644 -p $RPM_SOURCE_DIR/$f \
        $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.modules.d/$f
done

for f in welcome.conf ssl.conf manual.conf userdir.conf; do
  install -m 644 -p $RPM_SOURCE_DIR/$f \
        $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/$f
done

# Split-out extra config shipped as default in conf.d:
for f in autoindex; do
  mv docs/conf/extra/httpd-${f}.conf \
        $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/${f}.conf
done

# Extra config trimmed:
rm -v docs/conf/extra/httpd-{ssl,userdir}.conf

rm $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf/*.conf
install -m 644 -p $RPM_SOURCE_DIR/httpd.conf \
   $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf/httpd.conf

mkdir $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
for s in httpd htcacheclean; do
  install -m 644 -p $RPM_SOURCE_DIR/${s}.sysconf \
                    $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/${s}
done

# tmpfiles.d configuration
mkdir -p $RPM_BUILD_ROOT%{_prefix}/lib/tmpfiles.d 
install -m 644 -p $RPM_SOURCE_DIR/httpd.tmpfiles \
   $RPM_BUILD_ROOT%{_prefix}/lib/tmpfiles.d/httpd.conf

# Other directories
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/lib/dav \
         $RPM_BUILD_ROOT/run/httpd/htcacheclean

# Create cache directory
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/cache/httpd \
         $RPM_BUILD_ROOT%{_localstatedir}/cache/httpd/proxy \
         $RPM_BUILD_ROOT%{_localstatedir}/cache/httpd/ssl

# Make the MMN accessible to module packages
echo %{mmnisa} > $RPM_BUILD_ROOT%{_includedir}/httpd/.mmn
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/rpm
cat > $RPM_BUILD_ROOT%{_sysconfdir}/rpm/macros.httpd <<EOF
%%_httpd_mmn %{mmnisa}
%%_httpd_apxs %{_bindir}/apxs
%%_httpd_modconfdir %{_sysconfdir}/httpd/conf.modules.d
%%_httpd_confdir %{_sysconfdir}/httpd/conf.d
%%_httpd_contentdir %{contentdir}
%%_httpd_moddir %{_libdir}/httpd/modules
EOF

# Handle contentdir
mkdir $RPM_BUILD_ROOT%{contentdir}/noindex
tar xzf $RPM_SOURCE_DIR/centos-noindex.tar.gz \
        -C $RPM_BUILD_ROOT%{contentdir}/noindex/ \
        --strip-components=1

rm -rf %{contentdir}/htdocs

# remove manual sources
find $RPM_BUILD_ROOT%{contentdir}/manual \( \
    -name \*.xml -o -name \*.xml.* -o -name \*.ent -o -name \*.xsl -o -name \*.dtd \
    \) -print0 | xargs -0 rm -f

# Strip the manual down just to English and replace the typemaps with flat files:
set +x
for f in `find $RPM_BUILD_ROOT%{contentdir}/manual -name \*.html -type f`; do
   if test -f ${f}.en; then
      cp ${f}.en ${f}
      rm ${f}.*
   fi
done
set -x

# Clean Document Root
rm -v $RPM_BUILD_ROOT%{docroot}/html/*.html \
      $RPM_BUILD_ROOT%{docroot}/cgi-bin/*

# Symlink for the powered-by-$DISTRO image:
ln -s ../noindex/images/poweredby.png \
        $RPM_BUILD_ROOT%{contentdir}/icons/poweredby.png

# symlinks for /etc/httpd
ln -s ../..%{_localstatedir}/log/httpd $RPM_BUILD_ROOT/etc/httpd/logs
ln -s /run/httpd $RPM_BUILD_ROOT/etc/httpd/run
ln -s ../..%{_libdir}/httpd/modules $RPM_BUILD_ROOT/etc/httpd/modules

# install http-ssl-pass-dialog
mkdir -p $RPM_BUILD_ROOT%{_libexecdir}
install -m755 $RPM_SOURCE_DIR/httpd-ssl-pass-dialog \
	$RPM_BUILD_ROOT%{_libexecdir}/httpd-ssl-pass-dialog

# Install action scripts
mkdir -p $RPM_BUILD_ROOT%{_libexecdir}/initscripts/legacy-actions/httpd
for f in graceful configtest; do
    install -p -m 755 $RPM_SOURCE_DIR/action-${f}.sh \
            $RPM_BUILD_ROOT%{_libexecdir}/initscripts/legacy-actions/httpd/${f}
done

# Install logrotate config
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
install -m 644 -p $RPM_SOURCE_DIR/httpd.logrotate \
	$RPM_BUILD_ROOT/etc/logrotate.d/httpd

# fix man page paths
sed -e "s|/usr/local/apache2/conf/httpd.conf|/etc/httpd/conf/httpd.conf|" \
    -e "s|/usr/local/apache2/conf/mime.types|/etc/mime.types|" \
    -e "s|/usr/local/apache2/conf/magic|/etc/httpd/conf/magic|" \
    -e "s|/usr/local/apache2/logs/error_log|/var/log/httpd/error_log|" \
    -e "s|/usr/local/apache2/logs/access_log|/var/log/httpd/access_log|" \
    -e "s|/usr/local/apache2/logs/httpd.pid|/run/httpd/httpd.pid|" \
    -e "s|/usr/local/apache2|/etc/httpd|" < docs/man/httpd.8 \
  > $RPM_BUILD_ROOT%{_mandir}/man8/httpd.8

# Make ap_config_layout.h libdir-agnostic
sed -i '/.*DEFAULT_..._LIBEXECDIR/d;/DEFAULT_..._INSTALLBUILDDIR/d' \
    $RPM_BUILD_ROOT%{_includedir}/httpd/ap_config_layout.h

# Fix path to instdso in special.mk
sed -i '/instdso/s,top_srcdir,top_builddir,' \
    $RPM_BUILD_ROOT%{_libdir}/httpd/build/special.mk

# Remove unpackaged files
rm -vf \
      $RPM_BUILD_ROOT%{_libdir}/*.exp \
      $RPM_BUILD_ROOT/etc/httpd/conf/mime.types \
      $RPM_BUILD_ROOT%{_libdir}/httpd/modules/*.exp \
      $RPM_BUILD_ROOT%{_libdir}/httpd/build/config.nice \
      $RPM_BUILD_ROOT%{_bindir}/{ap?-config,dbmmanage} \
      $RPM_BUILD_ROOT%{_sbindir}/{checkgid,envvars*} \
      $RPM_BUILD_ROOT%{contentdir}/htdocs/* \
      $RPM_BUILD_ROOT%{_mandir}/man1/dbmmanage.* \
      $RPM_BUILD_ROOT%{contentdir}/cgi-bin/*

rm -rf $RPM_BUILD_ROOT/etc/httpd/conf/{original,extra}

%pre
# Add the "apache" group and user
/usr/sbin/groupadd -g 48 -r apache 2> /dev/null || :
/usr/sbin/useradd -c "Apache" -u 48 -g apache \
	-s /sbin/nologin -r -d %{contentdir} apache 2> /dev/null || :

%post
%systemd_post httpd.service htcacheclean.service

%preun
%systemd_preun httpd.service htcacheclean.service

%postun
%systemd_postun

# Trigger for conversion from SysV, per guidelines at:
# https://fedoraproject.org/wiki/Packaging:ScriptletSnippets#Systemd
%triggerun -- httpd < 2.2.21-5
# Save the current service runlevel info
# User must manually run systemd-sysv-convert --apply httpd
# to migrate them to systemd targets
/usr/bin/systemd-sysv-convert --save httpd.service >/dev/null 2>&1 ||:

# Run these because the SysV package being removed won't do them
/sbin/chkconfig --del httpd >/dev/null 2>&1 || :

%posttrans
test -f /etc/sysconfig/httpd-disable-posttrans || \
  /bin/systemctl try-restart httpd.service htcacheclean.service >/dev/null 2>&1 || :

%define sslcert %{_sysconfdir}/pki/tls/certs/localhost.crt
%define sslkey %{_sysconfdir}/pki/tls/private/localhost.key

%post -n mod_ssl
umask 077

if [ -f %{sslkey} -o -f %{sslcert} ]; then
   exit 0
fi

%{_bindir}/openssl genrsa -rand /proc/apm:/proc/cpuinfo:/proc/dma:/proc/filesystems:/proc/interrupts:/proc/ioports:/proc/pci:/proc/rtc:/proc/uptime 2048 > %{sslkey} 2> /dev/null

FQDN=`hostname`
if [ "x${FQDN}" = "x" -o ${#FQDN} -gt 59 ]; then
   FQDN=localhost.localdomain
fi

cat << EOF | %{_bindir}/openssl req -new -key %{sslkey} \
         -x509 -sha256 -days 365 -set_serial $RANDOM -extensions v3_req \
         -out %{sslcert} 2>/dev/null
--
SomeState
SomeCity
SomeOrganization
SomeOrganizationalUnit
${FQDN}
root@${FQDN}
EOF

%check
# Check the built modules are all PIC
if readelf -d $RPM_BUILD_ROOT%{_libdir}/httpd/modules/*.so | grep TEXTREL; then
   : modules contain non-relocatable code
   exit 1
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)

%doc ABOUT_APACHE README CHANGES LICENSE VERSIONING NOTICE
%doc docs/conf/extra/*.conf

%dir %{_sysconfdir}/httpd
%{_sysconfdir}/httpd/modules
%{_sysconfdir}/httpd/logs
%{_sysconfdir}/httpd/run
%dir %{_sysconfdir}/httpd/conf
%config(noreplace) %{_sysconfdir}/httpd/conf/httpd.conf
%config(noreplace) %{_sysconfdir}/httpd/conf/magic

%config(noreplace) %{_sysconfdir}/logrotate.d/httpd

%dir %{_sysconfdir}/httpd/conf.d
%{_sysconfdir}/httpd/conf.d/README
%config(noreplace) %{_sysconfdir}/httpd/conf.d/*.conf
%exclude %{_sysconfdir}/httpd/conf.d/ssl.conf
%exclude %{_sysconfdir}/httpd/conf.d/manual.conf

%dir %{_sysconfdir}/httpd/conf.modules.d
%config(noreplace) %{_sysconfdir}/httpd/conf.modules.d/*.conf
%exclude %{_sysconfdir}/httpd/conf.modules.d/00-ssl.conf
%exclude %{_sysconfdir}/httpd/conf.modules.d/00-proxyhtml.conf
%exclude %{_sysconfdir}/httpd/conf.modules.d/01-ldap.conf
%exclude %{_sysconfdir}/httpd/conf.modules.d/01-session.conf

%config(noreplace) %{_sysconfdir}/sysconfig/ht*
%{_prefix}/lib/tmpfiles.d/httpd.conf

%dir %{_libexecdir}/initscripts/legacy-actions/httpd
%{_libexecdir}/initscripts/legacy-actions/httpd/*

%{_sbindir}/ht*
%{_sbindir}/fcgistarter
%{_sbindir}/apachectl
%{_sbindir}/rotatelogs
%caps(cap_setuid,cap_setgid+pe) %attr(510,root,%{suexec_caller}) %{_sbindir}/suexec

%dir %{_libdir}/httpd
%dir %{_libdir}/httpd/modules
%{_libdir}/httpd/modules/mod*.so
%exclude %{_libdir}/httpd/modules/mod_auth_form.so
%exclude %{_libdir}/httpd/modules/mod_ssl.so
%exclude %{_libdir}/httpd/modules/mod_*ldap.so
%exclude %{_libdir}/httpd/modules/mod_proxy_html.so
%exclude %{_libdir}/httpd/modules/mod_xml2enc.so
%exclude %{_libdir}/httpd/modules/mod_session*.so

%dir %{contentdir}
%dir %{contentdir}/icons
%dir %{contentdir}/error
%dir %{contentdir}/error/include
%dir %{contentdir}/noindex
%{contentdir}/icons/*
%{contentdir}/error/README
%{contentdir}/error/*.var
%{contentdir}/error/include/*.html
%{contentdir}/noindex/*

%dir %{docroot}
%dir %{docroot}/cgi-bin
%dir %{docroot}/html

%attr(0710,root,apache) %dir /run/httpd
%attr(0700,apache,apache) %dir /run/httpd/htcacheclean
%attr(0700,root,root) %dir %{_localstatedir}/log/httpd
%attr(0700,apache,apache) %dir %{_localstatedir}/lib/dav
%attr(0700,apache,apache) %dir %{_localstatedir}/cache/httpd
%attr(0700,apache,apache) %dir %{_localstatedir}/cache/httpd/proxy

%{_mandir}/man8/*

%{_unitdir}/*.service

%files tools
%defattr(-,root,root)
%{_bindir}/*
%{_mandir}/man1/*
%doc LICENSE NOTICE
%exclude %{_bindir}/apxs
%exclude %{_mandir}/man1/apxs.1*

%files manual
%defattr(-,root,root)
%{contentdir}/manual
%config(noreplace) %{_sysconfdir}/httpd/conf.d/manual.conf

%files -n mod_ssl
%defattr(-,root,root)
%{_libdir}/httpd/modules/mod_ssl.so
%config(noreplace) %{_sysconfdir}/httpd/conf.modules.d/00-ssl.conf
%config(noreplace) %{_sysconfdir}/httpd/conf.d/ssl.conf
%attr(0700,apache,root) %dir %{_localstatedir}/cache/httpd/ssl
%{_libexecdir}/httpd-ssl-pass-dialog

%files -n mod_proxy_html
%defattr(-,root,root)
%{_libdir}/httpd/modules/mod_proxy_html.so
%{_libdir}/httpd/modules/mod_xml2enc.so
%config(noreplace) %{_sysconfdir}/httpd/conf.modules.d/00-proxyhtml.conf

%files -n mod_ldap
%defattr(-,root,root)
%{_libdir}/httpd/modules/mod_*ldap.so
%config(noreplace) %{_sysconfdir}/httpd/conf.modules.d/01-ldap.conf

%files -n mod_session
%defattr(-,root,root)
%{_libdir}/httpd/modules/mod_session*.so
%{_libdir}/httpd/modules/mod_auth_form.so
%config(noreplace) %{_sysconfdir}/httpd/conf.modules.d/01-session.conf

%files devel
%defattr(-,root,root)
%{_includedir}/httpd
%{_bindir}/apxs
%{_mandir}/man1/apxs.1*
%dir %{_libdir}/httpd/build
%{_libdir}/httpd/build/*.mk
%{_libdir}/httpd/build/*.sh
%{_sysconfdir}/rpm/macros.httpd

