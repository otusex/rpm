#!/bin/bash

yum -y  install epel-release  git rsync rpm-build-libs.x86_64 rpm-devel.x86_64 rpmdevtools.noarch
yum install -y xmlto zlib-devel libselinux-devel lua-devel apr-devel apr-util-devel pcre-devel systemd-devel openssl-devel libxml2-devel
yum group install "Development Tools" -y

cd ~

git clone https://github.com/otusex/rpm.git

mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

echo "Sync files..."
sleep 5
rsync -auxvHP rpm/rpmbuild/ rpmbuild/

cd  ~/rpmbuild/SPECS

rpmbuild -bb httpd.spec

mkdir -p /home/vagrant/web/repos/7/httpd/x86_64

cd ..
rsync -auxvHP RPMS/x86_64/ /home/vagrant/web/repos/7/httpd/x86_64/

chown -R vagrant:vagrant /home/vagrant/web

yum update -y
yum install createrepo yum-utils -y 

createrepo -v  /home/vagrant/web/repos/7/httpd/x86_64/
createrepo /home/vagrant/web/repos/7/httpd/x86_64/ -g /home/vagrant/web/repos/7/httpd/x86_64/repodata/repomd.xml

yum install -y yum-priorities

cat << EOF > /etc/yum.repos.d/IvanShuhai.repo
[IvanShuhai]
name=Repo by Ivan Shuhai
baseurl=file:///home/vagrant/web/repos/7/httpd/x86_64/
enabled=1
gpgcheck=0
priority=1
EOF

yum update -y

echo "Show our repo IvanShuhai"
yum list available | grep IvanShuhai

sleep 5
