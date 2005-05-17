#!/bin/sh

PREFIX=simta

if [ $# != "2" ]; then
    echo usage: $0 user domain
    exit 1
fi

if [ ]; then {
### Ambiguous Addresses
echo Test: Ambiguous mail, hit Return on all tests to continue
read $r
/usr/sbin/sendmail "john.smith@umich.edu" < text_ambiguous
echo Check: ambiguous mail bounces

### Group mail
echo Set: Create the group $1.$PREFIX.simple
echo Test: Simple group mail, hit Return
read $r
/usr/sbin/sendmail $1.$PREFIX.simple@$2 < text_group_simple
echo Check: see that you get the simple group mail verification

### Vacation
echo Set: your vacation on for $1@$2
echo Test: Vacation, hit Return
read $r
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1@$2 < text_vacation
echo Check: verify vacation worked.
echo Set: Turn your vacation off

### Included groups
echo Set: Create the group $1.$PREFIX.moderated
echo Set: Replace $1.$PREFIX.simple members with $1.$PREFIX.moderated
echo Test: Nested group mail, hit Return
read $r
/usr/sbin/sendmail $1.$PREFIX.simple@$2 < text_group_nested
echo Check: Email goes through $1.$PREFIX.moderated to you

### Group-owners mail
echo Test: Group-owner mail, hit Return
read $r
/usr/sbin/sendmail $1.$PREFIX.simple-owners@$2 < text_owners
echo Check: to see that you get the group owners mail verification

### Group-errors mail
echo Test: group-errors mail, hit Return
read $r
/usr/sbin/sendmail $1.$PREFIX.simple-errors@$2 < text_errors
echo Check: that errors-to defaults to owner
echo Set: the errors-to field of $1.$PREFIX.simple to $1.$PREFIX.moderated
read $r
/usr/sbin/sendmail $1.$PREFIX.simple-errors@$2 < text_errors
echo Check to see that the errors-to went through both groups

### Group-requests mail
echo Test: group-requests mail, hit Return
read $r
/usr/sbin/sendmail $1.$PREFIX.simple-requests@$2 < text_requests
echo Check: group-requests mail defaults to owner
echo Set: requests-to field of $1.$PREFIX.group to $1.$PREFIX.moderated
read $r
/usr/sbin/sendmail $1.$PREFIX.simple-requests@$2 < text_requests
echo Check: to see that the requests-to went through both groups

### LOOPS moderated groups
#loop case
echo Set: moderator field of $1.$PREFIX.moderated to $1.$PREFIX.moderated@$2
echo Test: Moderator Loop
read $r
/usr/sbin/sendmail $1.$PREFIX.moderated@$2 < text_moderated
echo Check: see that you get a moderator loop bounce message
#double loop case 1
echo Set: errors-to field of $1.$PREFIX.moderated to $1.$PREFIX.moderated@$2
echo Test: Error Loop 1
read $r
/usr/sbin/sendmail $1.$PREFIX.simple@$2 < text_moderated
echo Check: to see that the error message went to postmaster
#double loop case 2
echo Set: email errors-to field of $1.$PREFIX.moderated to $1.$PREFIX.moderated@$2
echo Test: Error Loop 2
read $r
/usr/sbin/sendmail $1.$PREFIX.simple@$2 < text_moderated
echo Check: to see that the error message went to postmaster
echo Set: clear error-to field
#double loop case 3
echo Test: Error Loop 3
read $r
/usr/sbin/sendmail $1.$PREFIX.simple@$2 < text_moderated
echo Check: to see that the error message went to postmaster
echo Set: clear email Errors-to.  

### GRID moderated groups
# GRID - moderated group: moderator
echo Set: create $1.$PREFIX.moderator
echo Set: replace moderator with $1.$PREFIX.moderator
echo Set: create $1.$PREFIX.member
echo Set: replace moderatored groups memebers with $1.$PREFIX.member
echo Test: Grid - moderated group: moderator
read $r
/usr/sbin/sendmail -f $1.$PREFIX.moderator@$2 $1.$PREFIX.moderated@$2 < text_moderated
echo Check: to see that the mail went through the group.
# GRID - moderated group: member, direct
echo Test: GRID - moderated group: member, direct
read $r
/usr/sbin/sendmail -f epcjr.simta.member@$2 $1.$PREFIX.moderated@$2 < text_moderated
echo Check to see that the mail went through the moderator.
# GRID - moderated group: not member, direct
echo Test: GRID - moderated group: not member, direct
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.moderated@$2 < text_moderated
read $r
echo Check to see that the mail went through the moderator.
# GRID - moderated group: member, not permitted
echo Test: GRID - moderated group: not member, not permitted
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.simple@$2 < text_moderated
read $r
echo Check to see that the mail went through the moderator.
# GRID - moderated group: not member, not permitted
echo Test: GRID - moderated group: not member, not permitted
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.simple@$2 < text_moderated
read $r
echo Check to see that the mail went through the moderator.
echo Set: Create $1.$PREFIX.permitted, ETC
# GRID - moderated group: member, permitted
echo Test: GRID - moderated group: member, permitted
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.permitted@$2 < text_moderated
read $r
echo Check to see that the mail went through the moderator.
# GRID - moderated group: not member, permitted
echo Test: GRID - moderated group: not member, permitted
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.permitted@$2 < text_moderated
read $r
echo Check to see that the mail went through the moderator.

### GRID - memonly group: member, direct
echo Set: create $1.$PREFIX.memonly
echo Set: replace memonly groups memebers with $1.$PREFIX.member
echo Set: memonly flag
echo Set: modify simple group, permitted group 
echo Test: Grid - memonly group: member, direct
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check to see that the mail went through the memonly group.
# GRID - memonly group: not member, direct
echo Test: GRID - memonly group: not member, direct
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check to see that you got a bounce
# GRID - memonly group: member, permitted group
echo Test: GRID - memonly group: member, permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD
# GRID - memonly group: not member, permitted group
echo Test: GRID - memonly group: not member, permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD
# GRID - memonly group: member, not permitted group
echo Test: GRID - memonly group: member, not permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.simple@$2 < text_memonly
echo Check: GOOD
# GRID - memonly group: not member, not permitted group
echo Test: GRID - memonly group: not member, not permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.simple@$2 < text_memonly
echo Check: BOUNCE

### GRID - private memonly group: member, direct
echo Set: modify $1.$PREFIX.memonly, Set private flag
echo Test: GRID - private memonly group: member, direct
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check to see that the mail went through the memonly group.
# GRID - private memonly group: not member, direct
echo Test: GRID - private memonly group: not member, direct
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check to see that you got a bounce
# GRID - private memonly group: member, permitted group
echo Test: GRID - private memonly group: member, permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD
# GRID - private memonly group: not member, permitted group
echo Test: GRID - private memonly group: not member, permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD
# GRID - private memonly group: member, not permitted group
echo Test: GRID - private memonly group: member, not permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.simple@$2 < text_memonly
echo Check: GOOD
# GRID - private memonly group: not member, not permitted group
echo Test: GRID - private memonly group: not member, not permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.simple@$2 < text_memonly
echo Check: BIT BUCKET

### GRID - moderated memonly group: moderator, direct
echo Set: modify $1.$PREFIX.memonly, Set moderator flag
echo Test: GRID - moderated memonly group: moderator, direct
read $r
/usr/sbin/sendmail -f $1.$PREFIX.moderator@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check: GOOD
# GRID - moderated memonly group: member, direct
echo Test: GRID - moderated memonly group: member, direct
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check: GOOD
# GRID - moderated memonly group: not member, direct
echo Test: GRID - moderated memonly group: not member, direct
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check: MODERATOR
# GRID - moderated memonly group: moderator, permitted
echo Test: GRID - moderated memonly group: moderator, permitted
read $r
/usr/sbin/sendmail -f $1.$PREFIX.moderator@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD
# GRID - moderated memonly group: member, permitted group
echo Test: GRID - moderated memonly group: member, permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD
# GRID - moderated memonly group: not member, permitted group
echo Test: GRID - moderated memonly group: not member, permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD
# GRID - moderated memonly group: moderator, not permitted
echo Test: GRID - moderated memonly group: moderator, not permitted
read $r
/usr/sbin/sendmail -f $1.$PREFIX.moderator@$2 $1.$PREFIX.simple@$2 < text_memonly
echo Check: GOOD
# GRID - moderated memonly group: member, not permitted group
echo Test: GRID - moderated memonly group: member, not permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.simple@$2 < text_memonly
echo Check: GOOD
# GRID - moderated memonly group: not member, not permitted group
echo Test: GRID - moderated memonly group: not member, not permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.simple@$2 < text_memonly
echo Check: MODERATOR

} fi;
### WORK HERE

### GRID - private moderated memonly group: moderator, direct
echo Set: modify $1.$PREFIX.memonly, Set private moderator flag
echo Test: GRID - private moderated memonly group: moderator, direct
read $r
/usr/sbin/sendmail -f $1.$PREFIX.moderator@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check: GOOD
# GRID - private moderated memonly group: member, direct
echo Test: GRID - private moderated memonly group: member, direct
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check: GOOD
# GRID - private moderated memonly group: not member, direct
echo Test: GRID - private moderated memonly group: not member, direct
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check: MODERATOR
# GRID - private moderated memonly group: moderator, permitted
echo Test: GRID - private moderated memonly group: moderator, permitted
read $r
/usr/sbin/sendmail -f $1.$PREFIX.moderator@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD
# GRID - private moderated memonly group: member, permitted group
echo Test: GRID - private moderated memonly group: member, permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD
# GRID - private moderated memonly group: not member, permitted group
echo Test: GRID - private moderated memonly group: not member, permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD
# GRID - private moderated memonly group: moderator, not permitted
echo Test: GRID - private moderated memonly group: moderator, not permitted
read $r
/usr/sbin/sendmail -f $1.$PREFIX.moderator@$2 $1.$PREFIX.simple@$2 < text_memonly
echo Check: GOOD
# GRID - private moderated memonly group: member, not permitted group
echo Test: GRID - private moderated memonly group: member, not permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.simple@$2 < text_memonly
echo Check: GOOD
# GRID - private moderated memonly group: not member, not permitted group
echo Test: GRID - private moderated memonly group: not member, not permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.simple@$2 < text_memonly
echo Check: MODERATOR



exit 0



#XXX Multiple DN

# supress no email

