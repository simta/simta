simta
=====

[![build](https://github.com/simta/simta/actions/workflows/build.yml/badge.svg)](https://github.com/simta/simta/actions/workflows/build.yml)

Background
----------

simta, the Simple Internet Mail Transfer Agent, was developed at the
University of Michigan. It is designed to integrate closely with our
LDAP directory, to be simple to configure and use, and to produce
useful logs.

Dependencies
------------

simta is developed and used mainly on Linux systems, but tries to
avoid gratuitous incompatibility with other Unix-like systems.

In order to build simta, you will need the following:

* A C compiler. Compilation has been tested with [GCC](https://gcc.gnu.org/)
  and [clang](https://clang.llvm.org/), and other modern compilers should
  also work.
* make
* pkg-config or a compatible replacement.
* [denser](https://github.com/simta/denser)
* [libsnet](https://github.com/simta/libsnet)
* [libucl](https://github.com/vstakhov/libucl)

There are also a number of optional dependencies (listed more-or-less in
decreasing order of importance):

* [OpenSSL](https://openssl.org/) >= 1.1.0
* [OpenDKIM](http://www.opendkim.org/)
* [OpenARC](https://github.com/trusteddomainproject/OpenARC)
* [jemalloc](http://jemalloc.net/)
* [LMDB](https://symas.com/lightning-memory-mapped-database/)
* [OpenLDAP](https://www.openldap.org/)
* [Libidn2](https://gitlab.com/libidn/libidn2)
* [Cyrus SASL](https://www.cyrusimap.org/sasl/)
* tcp_wrappers


Building and Installation
-------------------------

See [the included documentation](INSTALL) for general instructions on
using the build system. Refer to the output of `./configure --help`
for available configuration flags.

If you are building from a git checkout instead of a release tarball,
you will need to have some additional dependencies installed:

* [git](https://git-scm.com/)
* [Autoconf >= 2.63](https://www.gnu.org/software/autoconf/)
* [Automake](https://www.gnu.org/software/automake/)

Run `autoreconf -fi` to regenerate the build system, then proceed as normal.


Testing
-------

Tests can be run with `make check`. simta's test suite
requires Python >= 3.7, [pytest](https://pytest.org) >=
3.9, [aiosmtpd](https://pypi.org/project/aiosmtpd/),
[pyca/cryptography](https://pypi.org/project/cryptography/), and
[ruamel.yaml](https://pypi.org/project/ruamel.yaml/). You
may also want to install [cmocka](https://cmocka.org/) and pass
`--with-cmocka` to the `configure` script to enable additional unit
tests.

Some tests rely on spawning [YADIFA](https://www.yadifa.eu/) to
provide predictable DNS responses. If it is not available these tests
will be skipped.

Some tests require an LDAP server with [a specific set of
data](test/ldap/README.md). If the `LDAP_SERVER` environment variable
is not set these tests will be skipped. If LDAP is not set up
correctly these tests will fail.


Contact Us
----------

<simta@umich.edu>
