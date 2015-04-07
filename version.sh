#!/bin/sh

if [ -d .git ]; then
    git describe --tags | perl -pe 'chomp; s/simta-//; s/-/./ while ($i++ < 3); s/-.*//' | tee VERSION
elif [ -s VERSION ]; then
    cat VERSION
else
    echo -n UNKNOWN
fi
