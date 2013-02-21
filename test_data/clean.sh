#!/bin/sh

# make simta storage dirs
rm -f /var/spool/simta/slow/*
rm -f /var/spool/simta/fast/*
rm -f /var/spool/simta/local/*

# populate with some bad efiles
cp Ebad1 /var/spool/simta/local/
cp Ebad1 /var/spool/simta/local/Dbad1
cp Ebad2 /var/spool/simta/local/
cp Ebad2 /var/spool/simta/local/Dbad2
cp Ebad3 /var/spool/simta/local/
cp Ebad3 /var/spool/simta/local/Dbad3
cp Ebad4 /var/spool/simta/local/
cp Ebad4 /var/spool/simta/local/Dbad4
cp Ebad5 /var/spool/simta/local/
cp Ebad5 /var/spool/simta/local/Dbad5
cp Ebad6 /var/spool/simta/local/
cp Ebad6 /var/spool/simta/local/Dbad6
cp Ebad7 /var/spool/simta/local/
cp Ebad7 /var/spool/simta/local/Dbad7
cp Ebad8 /var/spool/simta/local/
cp Ebad8 /var/spool/simta/local/Dbad8

# tfiles
cp Eterminator /var/spool/simta/slow/tslow
cp Eterminator /var/spool/simta/fast/tfast
cp Eterminator /var/spool/simta/local/tlocal

# orphan E & D files
cp Eterminator /var/spool/simta/slow/Eorphan_se
cp Dterminator /var/spool/simta/slow/Dorphan_sd
cp Eterminator /var/spool/simta/fast/Eorphan_fe
cp Dterminator /var/spool/simta/fast/Dorphan_fd
cp Eterminator /var/spool/simta/local/Eorphan_le
cp Dterminator /var/spool/simta/local/Dorphan_ld

# pretend an expansion from FAST failed halfway through
cp Eunexpanded /var/spool/simta/fast/Eunexpn_f
cp Eunexpanded /var/spool/simta/fast/Dunexpn_f
cp Eexpanded /var/spool/simta/fast/Eexpn_f1
ln /var/spool/simta/fast/Dunexpn_f /var/spool/simta/fast/Dexpn_f1
cp Eexpanded /var/spool/simta/fast/Eexpn_f2
ln /var/spool/simta/fast/Dunexpn_f /var/spool/simta/fast/Dexpn_f2
cp Eexpanded /var/spool/simta/fast/Eexpn_f3
ln /var/spool/simta/fast/Dunexpn_f /var/spool/simta/fast/Dexpn_f3
cp Eexpanded /var/spool/simta/fast/Eexpn_f4
ln /var/spool/simta/fast/Dunexpn_f /var/spool/simta/fast/Dexpn_f4

# pretend an expansion from LOCAL failed halfway through
cp Eunexpanded /var/spool/simta/local/Eunexpn_l
cp Eunexpanded /var/spool/simta/local/Dunexpn_l
cp Eexpanded /var/spool/simta/fast/Eexpn_l1
ln /var/spool/simta/local/Dunexpn_l /var/spool/simta/fast/Dexpn_l1
cp Eexpanded /var/spool/simta/fast/Eexpn_l2
ln /var/spool/simta/local/Dunexpn_l /var/spool/simta/fast/Dexpn_l2
cp Eexpanded /var/spool/simta/fast/Eexpn_l3
ln /var/spool/simta/local/Dunexpn_l /var/spool/simta/fast/Dexpn_l3
cp Eexpanded /var/spool/simta/fast/Eexpn_l4
ln /var/spool/simta/local/Dunexpn_l /var/spool/simta/fast/Dexpn_l4

# pretend an expansion from SLOW failed halfway through
cp Eunexpanded /var/spool/simta/slow/Eunexpn_s
cp Eunexpanded /var/spool/simta/slow/Dunexpn_s
cp Eexpanded /var/spool/simta/fast/Eexpn_s1
ln /var/spool/simta/slow/Dunexpn_s /var/spool/simta/fast/Dexpn_s1
cp Eexpanded /var/spool/simta/fast/Eexpn_s2
ln /var/spool/simta/slow/Dunexpn_s /var/spool/simta/fast/Dexpn_s2
cp Eexpanded /var/spool/simta/fast/Eexpn_s3
ln /var/spool/simta/slow/Dunexpn_s /var/spool/simta/fast/Dexpn_s3
cp Eexpanded /var/spool/simta/fast/Eexpn_s4
ln /var/spool/simta/slow/Dunexpn_s /var/spool/simta/fast/Dexpn_s4

# expanded messages very normal
cp Eexpanded /var/spool/simta/slow/Enexpn_s1
cp Eexpanded /var/spool/simta/slow/Dnexpn_s1
cp Eexpanded /var/spool/simta/slow/Enexpn_s2
ln /var/spool/simta/slow/Dnexpn_s1 /var/spool/simta/slow/Dnexpn_s2
cp Eexpanded /var/spool/simta/slow/Enexpn_s3
ln /var/spool/simta/slow/Dnexpn_s1 /var/spool/simta/slow/Dnexpn_s3
cp Eexpanded /var/spool/simta/slow/Enexpn_s4
ln /var/spool/simta/slow/Dnexpn_s1 /var/spool/simta/slow/Dnexpn_s4

# failure halfway through moving a message from LOCAL to SLOW
cp Eexpanded /var/spool/simta/local/Dmv_ls
cp Eexpanded /var/spool/simta/local/Emv_ls
ln /var/spool/simta/local/Dmv_ls /var/spool/simta/slow/Dmv_ls
ln /var/spool/simta/local/Emv_ls /var/spool/simta/slow/Emv_ls

# failure halfway through moving a message from LOCAL to SLOW
cp Eexpanded /var/spool/simta/local/Dmv_ls2
cp Eexpanded /var/spool/simta/local/Emv_ls2
ln /var/spool/simta/local/Dmv_ls2 /var/spool/simta/slow/Dmv_ls2
ln /var/spool/simta/local/Emv_ls2 /var/spool/simta/slow/Emv_ls2

# failure halfway through moving a message from FAST to SLOW
cp Eexpanded /var/spool/simta/fast/Dmv_fs
cp Eexpanded /var/spool/simta/fast/Emv_fs
ln /var/spool/simta/fast/Dmv_fs /var/spool/simta/slow/Dmv_fs
ln /var/spool/simta/fast/Emv_fs /var/spool/simta/slow/Emv_fs

# failure halfway through moving a message from FAST to SLOW
cp Eexpanded /var/spool/simta/fast/Dmv_fs2
cp Eexpanded /var/spool/simta/fast/Emv_fs2
ln /var/spool/simta/fast/Dmv_fs2 /var/spool/simta/slow/Dmv_fs2
ln /var/spool/simta/fast/Emv_fs2 /var/spool/simta/slow/Emv_fs2
