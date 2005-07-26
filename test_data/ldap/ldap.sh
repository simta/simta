#!/bin/sh

PREFIX=simta

if [ $# != "2" ]; then
    echo usage: $0 user domain
    exit 1
fi

echo Please use the SIMSEND_STRICT_FROM_OFF directive in simta.conf for testing
echo

### Ambiguous Addresses
echo Test: Ambiguous mail, hit Return on all tests to continue
read $r
/usr/sbin/sendmail "john.smith@umich.edu" < text_ambiguous
echo Check: ambiguous mail bounces

## Vacation
echo Set: your vacation on for $1@$2
echo Test: Vacation, hit Return
read $r
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1@$2 < text_vacation
echo Check: verify vacation worked by checking the logs.
echo Set: Turn your vacation off

### Group mail
echo Set: \"$1 $PREFIX simple\" create group
echo Test: Simple group mail, hit Return
read $r
/usr/sbin/sendmail $1.$PREFIX.simple@$2 < text_group_simple
echo Check: see that you get the simple group mail verification

### Included groups
echo Set: \"$1 $PREFIX moderated\" create group
echo Set: \"$1 $PREFIX simple\" replace members \"$1 $PREFIX moderated\"
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
echo Set: \"$1 $PREFIX simple\" replace errors-to \"$1 $PREFIX moderated\"
read $r
/usr/sbin/sendmail $1.$PREFIX.simple-errors@$2 < text_errors
echo Check to see that the errors-to went through both groups

### Group-requests mail
echo Test: group-requests mail, hit Return
read $r
/usr/sbin/sendmail $1.$PREFIX.simple-requests@$2 < text_requests
echo Check: group-requests mail defaults to owner
echo Set: \"$1 $PREFIX simple\" replace requests-to \"$1 $PREFIX moderated\"
read $r
/usr/sbin/sendmail $1.$PREFIX.simple-requests@$2 < text_requests
echo Check: to see that the requests-to went through both groups

### LOOPS moderated groups
#loop case
echo Set: \"$1 $PREFIX moderated\" replace moderator \"$1.$PREFIX.moderated@$2\"
echo Test: Moderator Loop
read $r
/usr/sbin/sendmail $1.$PREFIX.moderated@$2 < text_moderated
echo Check: see that you get a moderator loop bounce message
#double loop case 1
echo Set: \"$1 $PREFIX moderated\" replace errors-to \"$1 $PREFIX moderated\"
echo Test: Error Loop 1
read $r
/usr/sbin/sendmail $1.$PREFIX.simple@$2 < text_moderated
echo Check: to see that the error message went to postmaster
#double loop case 2
echo Set: \"$1 $PREFIX moderated\" replace email errors-to \"$1.$PREFIX.moderated@$2\"
echo Test: Error Loop 2
read $r
/usr/sbin/sendmail $1.$PREFIX.simple@$2 < text_moderated
echo Check: to see that the error message went to postmaster
echo Set: \"$1 $PREFIX moderated\" clear errors-to
#double loop case 3
echo Test: Error Loop 3
read $r
/usr/sbin/sendmail $1.$PREFIX.simple@$2 < text_moderated
echo Check: to see that the error message went to postmaster

### GRID moderated groups
# GRID - moderated group: moderator
echo Set: \"$1 $PREFIX moderator\" create group
echo Set: \"$1 $PREFIX member\" create group
echo Set: \"$1 $PREFIX moderated\" replace groups memebers: \"$1 $PREFIX member\"
echo Set: \"$1 $PREFIX moderated\" clear email Errors-to
echo Set: \"$1 $PREFIX moderated\" replace moderator: \"$1.$PREFIX.moderator@$2\"
echo Test: Grid - moderated group: moderator
read $r
/usr/sbin/sendmail -f $1.$PREFIX.moderator@$2 $1.$PREFIX.moderated@$2 < text_moderated
echo Check: to see that the mail went through the members group.

# GRID - moderated group: member, direct
echo Test: GRID - moderated group: member, direct
read $r
/usr/sbin/sendmail -f epcjr.simta.member@$2 $1.$PREFIX.moderated@$2 < text_moderated
echo Check to see that the mail went through the moderator.

# GRID - moderated group: not member, direct
echo Test: GRID - moderated group: not member, direct
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.moderated@$2 < text_moderated
echo Check to see that the mail went through the moderator.

# GRID - moderated group: member, not permitted
echo Test: GRID - moderated group: not member, not permitted
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.moderated@$2 < text_moderated
echo Check to see that the mail went through the moderator.
# GRID - moderated group: not member, not permitted
echo Test: GRID - moderated group: not member, not permitted
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.moderated@$2 < text_moderated
echo Check to see that the mail went through the moderator.


# GRID - moderated group: member, permitted
echo Set: \"$1 $PREFIX permitted\" create group
echo Set: \"$1 $PREFIX permitted\" replace members: \"$1 $PREFIX moderated\"
echo Set: \"$1 $PREFIX moderated\" add permitted: \"$1 $PREFIX permitted\"
echo Test: GRID - moderated group: member, permitted
read $r
/usr/sbin/sendmail -f $1.$PREFIX.member@$2 $1.$PREFIX.permitted@$2 < text_moderated
echo Check to see that the mail went through the moderator.
# GRID - moderated group: not member, permitted
echo Test: GRID - moderated group: not member, permitted
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.permitted@$2 < text_moderated
echo Check to see that the mail went through the moderator.

### GRID - memonly group: member, direct
echo Set: NOT YET? modify simple group, permitted group 
echo Set: \"$1 $PREFIX memonly\" create
echo Set: \"$1 $PREFIX memonly\" replace members: \"$1 $PREFIX member\"
echo Set: \"$1 $PREFIX memonly\" set memonly TRUE
echo Test: Grid - memonly group: member, direct
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check to see that the mail went through the members group.

# GRID - memonly group: not member, direct
echo Set: \"$1 $PREFIX simple\" group delete
echo Set: \"$1 $PREFIX simple\" group create
echo Test: GRID - memonly group: not member, direct
read $r
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check to see that you got a bounce

# GRID - memonly group: member, permitted group
echo Set: \"$1 $PREFIX permitted\" membership replace \"$1 $PREFIX memonly\"
echo Set: \"$1 $PREFIX memonly\" permitted replace \"$1 $PREFIX permitted\"
echo Test: GRID - memonly group: member, permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: mail through simta memebers

# GRID - memonly group: not member, permitted group
echo Test: GRID - memonly group: not member, permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: mail through simta memebers

# GRID - memonly group: member, not permitted group
echo Set: \"$1 $PREFIX not permitted\" group create
echo Set: \"$1 $PREFIX not permitted\" membership replace \"$1 $PREFIX memonly\"
echo Test: GRID - memonly group: member, not permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.not.permitted@$2 < text_memonly
echo Check: mail through simta memebers

# GRID - memonly group: not member, not permitted group
echo Test: GRID - memonly group: not member, not permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.not.permitted@$2 < text_memonly
echo Check: BOUNCE

### GRID - private memonly group: member, direct
echo Set: \"$1 $PREFIX memonly\" enable private
echo Test: GRID - private memonly group: member, direct
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check to see that the mail went through the member group.

# GRID - private memonly group: not member, direct
echo Test: GRID - private memonly group: not member, direct
read $r
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.memonly@$2 < text_memonly
echo Check to see that you got a bounce

# GRID - private memonly group: member, permitted group
echo Test: GRID - private memonly group: member, permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: mail through member

# GRID - private memonly group: not member, permitted group
echo Test: GRID - private memonly group: not member, permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: mail through member

# GRID - private memonly group: member, not permitted group
echo Test: GRID - private memonly group: member, not permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.not.permitted@$2 < text_memonly
echo Check: mail through member

# GRID - private memonly group: not member, not permitted group
echo Test: GRID - private memonly group: not member, not permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.not.permitted@$2 < text_memonly
echo Check: BIT BUCKET

### GRID - moderated memonly group: moderator, direct
echo Set: \"$1 $PREFIX memonly\" replace moderator \"$1.$PREFIX.moderator@$2\"
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
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.memonly@$2 < text_memonly
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
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD

# GRID - moderated memonly group: moderator, not permitted
echo Test: GRID - moderated memonly group: moderator, not permitted
read $r
/usr/sbin/sendmail -f $1.$PREFIX.moderator@$2 $1.$PREFIX.not.permitted@$2 < text_memonly
echo Check: GOOD

# GRID - moderated memonly group: member, not permitted group
echo Test: GRID - moderated memonly group: member, not permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.not.permitted@$2 < text_memonly
echo Check: GOOD

# GRID - moderated memonly group: not member, not permitted group
echo Test: GRID - moderated memonly group: not member, not permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.not.permitted@$2 < text_memonly
echo Check: MODERATOR

### GRID - private moderated memonly group: moderator, direct
echo Set: \"$1 $PREFIX memonly\" enable private
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
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.memonly@$2 < text_memonly
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
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.permitted@$2 < text_memonly
echo Check: GOOD

# GRID - private moderated memonly group: moderator, not permitted
echo Test: GRID - private moderated memonly group: moderator, not permitted
read $r
/usr/sbin/sendmail -f $1.$PREFIX.moderator@$2 $1.$PREFIX.not.permitted@$2 < text_memonly
echo Check: GOOD

# GRID - private moderated memonly group: member, not permitted group
echo Test: GRID - private moderated memonly group: member, not permitted group
read $r
/usr/sbin/sendmail -f $1@$2 $1.$PREFIX.not.permitted@$2 < text_memonly
echo Check: GOOD

# GRID - private moderated memonly group: not member, not permitted group
echo Test: GRID - private moderated memonly group: not member, not permitted group
read $r
/usr/sbin/sendmail -f $1.$PREFIX.simple@$2 $1.$PREFIX.not.permitted@$2 < text_memonly
echo Check: MODERATOR

exit 0

#XXX Multiple DN

# supress no email

