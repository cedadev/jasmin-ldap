# jasmin-ldap

Library providing an improved interface to LDAP built on [ldap3](https://ldap3.readthedocs.org/):

  * Fully object-oriented
  * Connection pooling
  * Lazy, filterable search queries
  * A basic [data-mapper](https://en.wikipedia.org/wiki/Data_mapper_pattern)
    implementation


## Requirements and installation

The reference platform is a fully patched CentOS 6.x installation with Python 3.5
and access to an LDAP server.

To install Python 3.5 in CentOS 6.x, the following can be used:

```sh
sudo yum install https://centos6.iuscommunity.org/ius-release.rpm
sudo yum install python35u python35u-devel
```

The easiest way to install `jasmin-ldap` is to use [pip](https://pypi.python.org/pypi/pip),
which is included by default with Python 3.5.
```

`jasmin-ldap` is currently installed directly from Github:

```sh
# NOTE: This will install the LATEST versions of any dependent packages
#       For ways to do repeatable installs, see the pip documentation
pip install git+https://github.com/cedadev/jasmin-ldap.git@master
```


## Developing

Installing the `jasmin-ldap` library in development mode, via pip, ensures that
dependencies are installed and entry points are set up properly, but changes we
make to the source code are instantly picked up.

```sh
# Clone the repository
git clone https://github.com/cedadev/jasmin-ldap.git

# Install in editable (i.e. development) mode
#   NOTE: This will install the LATEST versions of any packages
#         This is what you want for development, as we should be keeping up to date!
pip install -e jasmin-ldap
```


## Generating the API documentation

Once you have successfully installed the `jasmin-ldap` code, you can generate
and view the API documentation:

```sh
cd doc
make clean html SPHINXBUILD=/path/to/sphinx-build
firefox _build/html/index.html
```
