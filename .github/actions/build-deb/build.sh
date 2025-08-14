#!/bin/bash -e

set -o pipefail

subd=$(git clone $1 2>&1 | grep 'Cloning into' | cut -d\' -f2)

pushd $subd
autoreconf -fi
./configure --prefix=/usr --disable-static
make -j4
mkdir -p ~/.tmp/$subd
make DESTDIR=~/.tmp/$subd install

pushd ~/.tmp/$subd
find . -name \*.la -delete
find .

# This is the kludgiest of kludges, but we only care about having installable
# packages, not whether they're correctly versioned.
fpm -s dir -t deb -n $subd -v 1.0 .
mkdir -p $2
mv -v $(echo $subd | tr A-Z a-z)_1.0_amd64.deb $2
