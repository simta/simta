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

# add junk files
cp Dseed ../slow/notgood
cp Dseed ../slow/useless

# 4 messages, 1 is unexpanded
cp Eexpanded ../slow/Em1
cp Eunexpanded ../slow/Em2
cp Eexpanded ../slow/Em3
cp Eexpanded ../slow/Em4
cp Dseed ../slow/Dm1
ln ../slow/Dm1 ../slow/Dm2
ln ../slow/Dm1 ../slow/Dm3
ln ../slow/Dm1 ../slow/Dm4

# 3 messages, all expanded
cp Eexpanded ../slow/Ex1
cp Eexpanded ../slow/Ex2
cp Eexpanded ../slow/Ex3
cp Dseed ../slow/Dx1
ln ../slow/Dx1 ../slow/Dx2
ln ../slow/Dx1 ../slow/Dx3

# populate FAST
cp Eexpanded ../fast/Efast1
cp Eexpanded ../fast/Efast2
cp Eexpanded ../fast/Efast3
cp Dseed ../fast/Dfast1
ln ../fast/Dfast1 ../fast/Dfast2
ln ../fast/Dfast1 ../fast/Dfast3
cp Dseed ../fast/tmp1
cp Dseed ../fast/tmp2
cp Dseed ../fast/junk

# populate LOCAL
cp Eexpanded ../local/Elocal
cp Dseed ../local/Dlocal
cp Dseed ../local/tp1
cp Dseed ../local/tp2
cp Dseed ../local/garbage
