#!/bin/sh

# make some old, bad mail
cp Dbounce /var/spool/simta/slow/
cp Ebounce /var/spool/simta/slow/
touch -t 01011111 /var/spool/simta/slow/Dbounce

cp Dbounce /var/spool/simta/slow/Dbounce1
cp Ebounce /var/spool/simta/slow/Ebounce1
touch -t 01011111 /var/spool/simta/slow/Dbounce1

cp Dbounce /var/spool/simta/slow/Dbounce2
cp Ebounce /var/spool/simta/slow/Ebounce2
touch -t 01011111 /var/spool/simta/slow/Dbounce2

cp Dbounce /var/spool/simta/slow/Dbounce3
cp Ebounce /var/spool/simta/slow/Ebounce3
touch -t 01011111 /var/spool/simta/slow/Dbounce3

cp Dbounce /var/spool/simta/slow/Dbounce4
cp Ebounce /var/spool/simta/slow/Ebounce4
touch -t 01011111 /var/spool/simta/slow/Dbounce4

cp Dbounce /var/spool/simta/slow/Dbounce5
cp Ebounce /var/spool/simta/slow/Ebounce5
touch -t 01011111 /var/spool/simta/slow/Dbounce5

cp Dbounce /var/spool/simta/slow/Dbounce6
cp Ebounce /var/spool/simta/slow/Ebounce6
touch -t 01011111 /var/spool/simta/slow/Dbounce6

cp Dbounce /var/spool/simta/slow/Dbounce7
cp Ebounce /var/spool/simta/slow/Ebounce7
touch -t 01011111 /var/spool/simta/slow/Dbounce7

cp Dbounce /var/spool/simta/slow/Dbounce8
cp Ebounce /var/spool/simta/slow/Ebounce8
touch -t 01011111 /var/spool/simta/slow/Dbounce8

cp Dbounce /var/spool/simta/slow/Dbounce9
cp Ebounce /var/spool/simta/slow/Ebounce9
touch -t 01011111 /var/spool/simta/slow/Dbounce9

cp Dbounce /var/spool/simta/slow/Dbounce10
cp Ebounce /var/spool/simta/slow/Ebounce10
touch -t 01011111 /var/spool/simta/slow/Dbounce10

chown -R simta /var/spool/simta/slow/*
chgrp -R simta /var/spool/simta/slow/*
