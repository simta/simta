simta
=====

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

* A C compiler. Compilation has been tested with [GCC] (https://gcc.gnu.org/)
  and [clang] (http://clang.llvm.org/), and other modern compilers should
  also work.
* make
* pkg-config or a compatible replacement.
* [denser] (https://github.com/simta/denser)
* [libsnet] (https://github.com/simta/libsnet)

There are also a number of optional dependencies (listed more-or-less in
decreasing order of importance):

* [jemalloc] (http://www.canonware.com/jemalloc/)
* [OpenSSL] (https://openssl.org/) or a compatible replacement such as
  [LibreSSL] (http://www.libressl.org/)
* [LMDB] (http://symas.com/mdb/)
* [OpenLDAP] (http://www.openldap.org/)
* [OpenDKIM] (http://www.opendkim.org/)
* [Libidn] (http://www.gnu.org/software/libidn/)
* [Cyrus SASL] (http://asg.web.cmu.edu/sasl/)
* tcp_wrappers


Building and Installation
-------------------------

See [the included documentation] (INSTALL) for general instructions on
using the build system. Refer to the output of `./configure --help`
for available configuration flags.

If you are building from a git checkout instead of a release tarball,
you will need to have some additional dependencies installed:

* [git] (https://git-scm.com/)
* [Autoconf >= 2.63] (https://www.gnu.org/software/autoconf/)
* [Automake] (https://www.gnu.org/software/automake/)

Run `autoreconf -fi` to regenerate the build system, then proceed as normal.

Contact Us
----------

<simta@umich.edu>
