#!/bin/sh

# make simta storage dirs
mkdir ../slow
mkdir ../fast
mkdir ../local

# add orphan E and D files
cp Eexpanded ../slow/Eorphan
cp Eunexpanded ../slow/Eunorphan
cp Dseed ../slow/Dalone

# add orphan tfiles
cp Dseed ../slow/t1
cp Dseed ../slow/t2
