#!/bin/sh

# make simta storage dirs
rm -f /var/spool/simta/slow/*

# deliver some rsug mail
cp Ersug /var/spool/simta/slow/
cp Drsug /var/spool/simta/slow/

# do a RSET smtp command to deliver 2 messages to RSUG
cp Ersug /var/spool/simta/slow/Ersug1
ln /var/spool/simta/slow/Drsug /var/spool/simta/slow/Drsug1

# deliver some terminator mail
cp Eterminator /var/spool/simta/slow/
cp Dterminator /var/spool/simta/slow/

# deliver some umich mail
cp Eumich /var/spool/simta/slow/
cp Dumich /var/spool/simta/slow/
