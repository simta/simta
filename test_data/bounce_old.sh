#!/bin/sh

# make some old, bad mail
cp Dbounce /var/spool/simta/slow/
cp Ebounce /var/spool/simta/slow/

# make it old
touch -t 01011111 /var/spool/simta/slow/Dbounce

chown -R simta /var/spool/simta/slow/*
chgrp -R simta /var/spool/simta/slow/*
