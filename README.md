# Create REPO

Install createrepo yum-utils need for create repo
```bash
yum install createrepo yum-utils
```


Creating directories for the repository

```bash
mkdir -p /path_to_docroot/repos/7/httpd/x86_64
```

After creating rpm packages, copy them to this directory

```bash
cp -rp *.rpm /path_to_docroot/repos/7/httpd/x86_64
```

Creating repositories:

```bash
createrepo -v /path_to_docroot/repos/7/httpd/x86_64
```

We also allow groups:

```bash
createrepo /path_to_docroot/repos/7/httpd/x86_64 -g /path_to_docroot/repos/7/httpd/x86_64/repodata/repomd.xml
```


Configuring nginx:

```bash
location /repos/ {
  index  index.html index.htm;
  autoindex on;
}

systemctl restart nginx
```

Add repo

```bash
cat << EOF > /etc/yum.repos.d/IvanShuhai.repo
[IvanShuhai]
name=Repo by Ivan Shuhai
baseurl=http://88.208.54.189/repos/$releasever/httpd/x86_64/
enabled=1
gpgcheck=0
EOF
```

Check repo, install httpd,httpd-devel

```bash
yum update
yum list available | grep IvanShuhai

yum install  yum install httpd-devel.x86_64 httpd-2.4.6-93.el7.x86_64
```


# Build RPM

Install rpmdevtools need for build rpm 

```bash
yum -y  install rpm-build-libs.x86_64 rpm-devel.x86_64 rpmdevtools.noarch
```

Install Dependencies for Apache 

```bash
yum install -y xmlto zlib-devel libselinux-devel lua-devel apr-devel apr-util-devel pcre-devel systemd-devel openssl-devel libxml2-devel
```

Install Dev tools

```bash
yum group install "Development Tools" -y
```

Creating a directory structure and go to user home dir

```bash
cd ~
mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
```

Create spec file

```bash
cd  ~/rpmbuild/SPECS

touch httpd.spec
```


After writing the spec file, run the build

```bash
rpmbuild -bb httpd.spec
```


Main commands in the file spec


```bash
Name, versio, source

Summary: Apache HTTP Server
Name: httpd
Version: 2.4.6
Release: 93%{?dist}
URL: http://httpd.apache.org/
Source0: http://www.apache.org/dist/httpd/httpd-%{version}.tar.bz2
Source1: centos-noindex.tar.gz
...


patchs

Patch1: httpd-2.4.1-apctl.patch
Patch2: httpd-2.4.3-apxs.patch
Patch3: httpd-2.4.1-deplibs.patch
...

BuildRequires AND Requires

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
...


preparation to build
%prep
%setup -q
%patch1 -p1 -b .apctl
%patch2 -p1 -b .apxs
...

Procces buid

%build

Build the daemon

%configure \
 	--prefix=%{_sysconfdir}/httpd \
 	--exec-prefix=%{_prefix} \
 	--bindir=%{_bindir} \
...

make %{?_smp_mflags}

See more in the file spec

```


