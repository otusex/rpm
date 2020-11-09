#Create REPO

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







