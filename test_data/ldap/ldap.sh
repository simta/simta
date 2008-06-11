#!/bin/sh

# ldap.sh:	A Bourne shell script to test the LDAP capabilities of
#		simta(8).  This script will be useful mostly during testing
#		and deployment of new versions of simta.
#
#		adbisaro@umich.edu
#		June 2008

TAG=simtatest
SENDMAIL="/usr/sbin/sendmail"
VERBOSE="on"
LDAP_URI=ldap://ldap-master.itd.umich.edu
TMPDIR=/tmp/,ldap-test,$$
GROUPNAMES=( simple moderated moderator member memonly permitted notpermitted )
LDAPMODIFY="ldapmodify -H ${LDAP_URI} -Q -v"
SLEEP=5

# --------------------------------------------------------------------
# Functions

verb() {
	if [ "$VERBOSE" ]; then
		echo $@
	fi
	$@
}

pause() {
	echo "Press Enter to continue, or ctrl-c to quit."
	read dummy;
}

begin_test() {
	testname=$1
	verify=$2
	testnum=$(( $testnum + 1 ))

	printf "\n\n"
	printf "Test #${testnum}:\t${testname}\n"
	printf "Verification:\t${verify}\n\n"
	printf "Begin test #${testnum}:  "
	pause
	date '+Test start time:  %b %e %T'
	printf "\n"
}

end_test() {
	echo ""
	echo "Test #${testnum} complete.  "
	echo ""
}

ldapmod() {
	cat - | $LDAPMODIFY
	echo "Sleeping for $SLEEP seconds"
	sleep $SLEEP
}

creategroups() {

	echo -n "Create test LDAP groups:  "
	pause
	echo
	for gtype in ${GROUPNAMES[@]}; do
        	cat ./group-add.ldif-template | \
        	sed -e "s/GTYPE/${gtype}/g;
                	s/UNIQNAME/${user}/g;
                	s/TAG/${TAG}/g;
                	s/DOMAIN/${domain}/g;"
		echo ""
	done | $LDAPMODIFY
	echo "Done creating test LDAP groups."
	pause
}

deletegroups() {

	echo "Cleanup:  Deleting test LDAP groups ... "
	for gtype in ${GROUPNAMES[@]} ; do
		a="cn=$user $TAG $gtype"
		b="ou=User Groups,ou=Groups,dc=umich,dc=edu"
		echo "dn: $a,$b"
		echo "changetype: delete"
		echo ""
	done | $LDAPMODIFY
	echo "Done deleting test LDAP groups."
}

cleanup() {

	deletegroups
	kdestroy

	if [ -d "$TMPDIR" ]; then
		if [ ! -s "${TMPDIR}/stderr" ]; then
			echo "Warning, stderr output captured:"
			echo ""
			cat ${TMPDIR}/stderr
		fi
		rm -fr $TMPDIR
	fi

}

mail_test() {
	from="$1"
	to="$2"
	name="$3"
	verify="$4"

	subject="LDAP test #${testnum}: $name"
	cmd="$SENDMAIL -f $from $to"

	${cmd}<<-_MAILTEST
		From: $from
		To: $to
		Subject: $subject

		Test Number:	$testnum
		Test Name:	$name


		Command:
		$cmd

		Expected Result:
		$verify

	_MAILTEST
}

# --------------------------------------------------------------------
# Main

if [ $# != "2" ]; then
    echo 'usage: ./ldap.sh <uniqname> <domain>'
    exit 1
fi

user=$1
domain=$2
LDAPMODIFY="${LDAPMODIFY} -U $user"
testnum=0


echo "Caveat Lector"
echo ""
echo "Please note that this is merely a set of tests conglomerated for"
echo "convenience, not a robust application.  You should read through this"
echo "script and have a fair understanding of what it does before you go any"
echo "further."
echo ""
echo "Make sure the SIMSEND_STRICT_FROM_OFF directive is set in your simta"
echo "configuration file (/etc/simta.conf).  This is required for all tests."
pause

wd=`echo $0 | sed -n -r -e 's,^(.*/)[^/][^/]*$,\1,p'`

# Testing the string is unnecessary in some cases, but maybe (?) not all.
# My version of bash(1), at least, prefixes $0 with ./ when I invoke it
# with no pathing (i.e., "." in my $PATH.  Hush, I set my $PATH like that
# only for testing.).

if [ "$wd" ]; then
	verb cd $wd
fi

mkdir -m 700 $TMPDIR || exit 1
exec 2> ${TMPDIR}/stderr
export KRB5CCNAME="FILE:${TMPDIR}/krb5cc_${user}"
verb kinit $user 2> /dev/null
echo ""
klist
echo ""
creategroups


# ----------------------------------
#           Begin Tests
# ----------------------------------

### Ambiguous Addresses
### -------------------

Name="Ambiguous address"
Result="Bounce to sender with LDAP lookup error message"
To="john.smith@umich.edu"
From="${user}@${domain}"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### Vacation
### --------

Name="Vacation"
Result="Mail logfile shows vacation worked"
To="${user}@${domain}"
From="${user}.${TAG}.simple@${domain}"

begin_test	"$Name" "$Result"

# ldap: Set your vacation on for ${user}@${domain}
ldapmod <<_END
dn: uid=${user},ou=People,dc=umich,dc=edu
changetype: modify
replace: onvacation
onvacation: TRUE
-
replace: vacationmessage
vacationmessage: \$Testing the 'vacation' function, please reset 'vacation' to
 False\$after 4 June 2008.
_END

mail_test	"$From" "$To" "$Name" "$Result"

# ldap: Turn your vacation off
ldapmod <<_END
dn: uid=${user},ou=People,dc=umich,dc=edu
changetype: modify
replace: onvacation
onvacation: FALSE
-
delete: vacationmessage
_END

end_test


### Group mail
### ----------

To="${user}.${TAG}.simple@${domain}"
From="${user}@${domain}"
Name="Simple Group"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### Included groups
### ---------------

To="${user}.${TAG}.simple@${domain}"
From="${user}@${domain}"
Name="Nested Group"
Result="Delivered through '$To' to Moderated"

begin_test	"$Name" "$Result"

# Replace "${user}.${TAG}.simple members with ${user}.${TAG}.moderated
ldapmod <<_END
dn: cn=$user $TAG simple,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: member
member: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### Group-owners mail
### -----------------

To="${user}.${TAG}.simple-owners@${domain}"
From="${user}@${domain}"
Name="Group Owner"
Result="Delivered to owner"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### Group-errors mail
### -----------------

To="${user}.${TAG}.simple-errors@${domain}"
From="${user}@${domain}"
Name="Group Errors"
Result="Delivered to owner"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### Group errors plus rfc822Errors
### ------------------------------

To="${user}.${TAG}.simple-errors@${domain}"
From="${user}@${domain}"
Name="Group Errors to rfc822ErrorsTo"
Result="Delivered through rfc822ErrorsTo"

begin_test	"$Name" "$Result"

# ldap: $user $TAG simple' add rfc822ErrorsTo $user $TAG moderated'
# ldap: $user $TAG simple' add errorsTo '${user}'
ldapmod <<_END
dn: cn=$user $TAG simple,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
add: rfc822ErrorsTo
rfc822ErrorsTo: ${user}.${TAG}.moderated@${domain}
-
changetype: modify
add: errorsTo
errorsTo: uid=${user},ou=People,dc=umich,dc=edu
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test



### Group-requests mail
### -------------------

To="${user}.${TAG}.simple-requests@${domain}"
From="${user}@${domain}"
Name="Group Requests"
Result="Delivered through group"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### Group-requests plus rfc822Requests
### ----------------------------------

To="${user}.${TAG}.simple-requests@${domain}"
From="${user}@${domain}"
Name="Group Requests to rfc822RequestsTo"
Result="Delivered through rfc822RequestsTo"

begin_test	"$Name" "$Result"

# ldap: $user $TAG simple' add requestsTo '$user'
# ldap: $user $TAG simple' add rfc822RequestsTo '$user $TAG moderated'
ldapmod <<_END
dn: cn=$user $TAG simple,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
add: requestsTo
requestsTo: uid=${user},ou=People,dc=umich,dc=edu
-
changetype: modify
add: rfc822RequestsTo
rfc822RequestsTo: ${user}.${TAG}.moderated
_END

mail_test	"$From" "$To" "$Name" "$Result"

# ldap: $user $TAG simple' replace errorsTo '${user}'
ldapmod <<_END
dn: cn=$user $TAG simple,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: errorsTo
errorsTo: uid=${user},ou=People,dc=umich,dc=edu
_END

end_test


# -----
# Loops
# -----


### Moderated Groups:  Moderator Loop
### ---------------------------------

To="${user}.${TAG}.moderated@${domain}"
From="${user}@${domain}"
Name="Moderator Loop"
Result="Bounce to sender with moderator loop error"

begin_test	"$Name" "$Result"

# ldap: '$user $TAG moderated' replace moderator $'{user}.${TAG}.moderated@${domain}'
# moderator: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
ldapmod <<_END
dn: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
add: moderator
moderator: ${user}.${TAG}.moderated@${domain}
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### Moderated Groups:  Double loop case 1
### -------------------------------------

# The previous case creates a loop, what happens when our loop-notification
# gets caught in a loop?  :)  Here errorsTo traps loop-notication in a loop.

To="${user}.${TAG}.simple@${domain}"
From="${user}@${domain}"
Name="Double Loop 1"
Result="Double-bounce to postmaster"

begin_test	"$Name" "$Result"

# ldap: '$user $TAG moderated' replace errorsTo '$user $TAG moderated'
ldapmod <<_END
dn: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
add: errorsTo
errorsTo: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### Moderated Groups:  Double loop case 2
### -------------------------------------

# Here both errorsTo and rfc822ErrorsTo trap loop-notication in a loop.

To="${user}.${TAG}.simple@${domain}"
From="${user}@${domain}"
Name="Double Loop 2"
Result="Double-bounce to postmaster"

begin_test	"$Name" "$Result"

# ldap: '$user $TAG moderated' replace rfc822ErrorsTo '${user}.${TAG}.simple@${domain}'
ldapmod <<_END
dn: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
add: rfc822ErrorsTo
rfc822ErrorsTo: ${user}.${TAG}.simple@${domain}
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### Moderated Groups:  Double loop case 3
### -------------------------------------

# Here only rfc822ErrorsTo traps loop-notication in a loop.

To="${user}.${TAG}.simple@${domain}"
From="${user}@${domain}"
Name="Double Loop 3"
Result="Double-bounce to postmaster"

begin_test	"$Name" "$Result"

# ldap: '$user $TAG moderated' clear errorsTo
ldapmod <<_END
dn: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
delete: errorsTo
_END

mail_test	"$From" "$To" "$Name" "$Result"

# ldap: '$user $TAG moderated' clear rfc822ErrorsTo
ldapmod <<_END
dn: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
delete: rfc822ErrorsTo
_END

end_test


# *************************************************************************
# Below "GRID" refers to a matrix of possible rfc822mailgroup behaviours.
# See http://rsug.itd.umich.edu/software/simta/grid.html.
# *************************************************************************


# ---------------
# Moderated Group
# ---------------

### GRID - moderated group: moderator
### ---------------------------------

To="${user}.${TAG}.moderated@${domain}"
From="${user}.${TAG}.moderator@${domain}"
Name="Moderator to Moderated"
Result="Delivered through '$To' to ${user}.${TAG}.members"

begin_test	"$Name" "$Result"

# ldap: $user $TAG moderated' replace groups members: '$user $TAG member'
# ldap: $user $TAG moderated' replace moderator: '${user}.${TAG}.moderator@${domain}'
ldapmod <<_END
dn: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: member
member: cn=$user $TAG member,ou=User Groups,ou=Groups,dc=umich,dc=edu
-
replace: moderator
moderator: ${user}.${TAG}.moderator@${domain}
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - moderated group: member, direct
### --------------------------------------

To="${user}.${TAG}.moderated@${domain}"
From="${user}.${TAG}.member@${domain}"
Name="Member, direct to Moderated"
Result="Delivered to moderator"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - moderated group: not member, direct
### ------------------------------------------

To="${user}.${TAG}.moderated@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not Member, direct to Moderated"
Result="Delivered to moderator"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - moderated group: member, not permitted
### ---------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}.${TAG}.member@${domain}"
Name="Member, through Not Permitted, to Moderated"
Result="Delivered to moderator"

begin_test	"$Name" "$Result"

# ldap: '$user $TAG notpermitted' membership replace with '$user $TAG moderated'
ldapmod <<_END
dn: cn=$user $TAG notpermitted,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: member
member: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test

### GRID - moderated group: not member, not permitted
### -------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not Member, through Not Permitted, to Moderated"
Result="Delivered to moderator"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - moderated group: member, permitted
### -----------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}.${TAG}.member@${domain}"
Name="Member, through Permitted, to Moderated"
Result="Delivered to moderator"

begin_test	"$Name" "$Result"


# ldap: '$user $TAG permitted' replace members: '$user $TAG moderated'
# ldap: '$user $TAG moderated' add permitted: '$user $TAG permitted'
ldapmod <<_END
dn: cn=$user $TAG permitted,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: member
member: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu

dn: cn=$user $TAG moderated,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: permittedGroup
permittedGroup: cn=$user $TAG permitted,ou=User Groups,ou=Groups,dc=umich,dc=edu
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test

### GRID - moderated group: not member, permitted
### ---------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not Member, through Permitted, to Moderated"
Result="Delivered to moderator"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test



# ------------------
# Members-Only Group
# ------------------

### GRID - memonly group: member, direct
### ------------------------------------

To="${user}.${TAG}.memonly@${domain}"
From="${user}@${domain}"
Name="Member, Direct, to Members Only"
Result="Delivered through '${user}.${TAG}.memonly-members'"

begin_test	"$Name" "$Result"

# ldap: '$user $TAG memonly' replace members: '$user $TAG member'
# ldap: '$user $TAG memonly' set memonly TRUE
ldapmod <<_END
dn: cn=$user $TAG memonly,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: member
member: cn=$user $TAG member,ou=User Groups,ou=Groups,dc=umich,dc=edu
-
add: Membersonly
Membersonly: TRUE
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - memonly group: not member, direct
### ----------------------------------------

To="${user}.${TAG}.memonly@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not Member, directly to Members Only"
Result="Bounce to sender with not-allowed error message"

begin_test	"$Name" "$Result"

# Reset the 'simple' group to a sane state.

# ldap: '$user $TAG simple' group delete and recreate
ldapmod <<_END
dn: cn=$user $TAG simple,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: delete
_END

cat ./group-add.ldif-template | \
        sed -e "s/GTYPE/simple/g;
               	s/UNIQNAME/${user}/g;
               	s/TAG/${TAG}/g;
               	s/DOMAIN/${domain}/g;" | \
	ldapmod

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - memonly group: member, permitted group
### ---------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}@${domain}"
Name="Member, through Permitted, to Members Only"
Result="Delivered through '${user}.${TAG}.memonly-members'"

begin_test	"$Name" "$Result"
# ldap: '$user $TAG permitted' membership replace '$user $TAG memonly'
# ldap: '$user $TAG memonly' replace permittedGroup '$user $TAG permitted'
ldapmod <<_END
dn: cn=$user $TAG permitted,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: member
member: cn=$user $TAG memonly,ou=User Groups,ou=Groups,dc=umich,dc=edu

dn: cn=$user $TAG memonly,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: permittedGroup
permittedGroup: cn=$user $TAG permitted,ou=User Groups,ou=Groups,dc=umich,dc=edu
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - memonly group: not member, permitted group
### -------------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not Member, through Permitted, to Members Only"
Result="Delivered through '${user}.${TAG}.memonly-members'"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - memonly group: member, not permitted group
### -------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}@${domain}"
Name="Member, through Not Permitted, to Members Only"
Result="Delivered through '${user}.${TAG}.memonly-members'"

begin_test	"$Name" "$Result"

# ldap: '$user $TAG notpermitted' membership replace '$user $TAG memonly'
ldapmod <<_END
dn: cn=$user $TAG notpermitted,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: member
member: cn=$user $TAG memonly,ou=User Groups,ou=Groups,dc=umich,dc=edu
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - memonly group: not member, not permitted group
### -----------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not Member, through Not Permitted, to Members Only"
Result="Bounce with not-allowed error"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test


# ------------------------------
# Private and Members Only group
# ------------------------------


### GRID - private memonly group: member, direct
### --------------------------------------------

To="${user}.${TAG}.memonly@${domain}"
From="${user}@${domain}"
Name="Member, direct to Private+MembersOnly"
Result="Delivered through '${user}.${TAG}.memonly-members@${domain}'"

begin_test	"$Name" "$Result"

# ldap: '$user $TAG memonly' enable private
ldapmod <<_END
dn: cn=$user $TAG memonly,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: rfc822Private
rfc822Private: TRUE
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test

### GRID - private memonly group: not member, direct
### ------------------------------------------------

To="${user}.${TAG}.memonly@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not member, direct to Private+MembersOnly"
Result="Bounce to sender with not allowed message"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test

### GRID - private memonly group: member, permitted group
### -----------------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}@${domain}"
Name="Member, through Permitted, to Private+MembersOnly"
Result="Delivered through '${user}.${TAG}.memonly-members'"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test

### GRID - private memonly group: not member, permitted group
### ---------------------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not member, through Permitted group, to Private+MembersOnly"
Result="Delivered through '${user}.${TAG}.memonly-members'"

begin_test	"$Name" "$Result"

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - private memonly group: member, not permitted group
### ---------------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}@${domain}"
Name="Member, through Not Permitted, to Private+MembersOnly"
Result="Delivered through '${user}.${TAG}.memonly-members'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - private memonly group: not member, not permitted group
### -------------------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not member, through Not permitted, to Private+MembersOnly"
Result="Discarded" 

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


# --------------------------------
# Moderated and Members Only group
# --------------------------------

### GRID - moderated memonly group: moderator, direct
### -------------------------------------------------

To="${user}.${TAG}.memonly@${domain}"
From="${user}.${TAG}.moderator@${domain}"
Name="Moderator, direct to Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"

# ldap: '$user $TAG memonly' replace moderator '${user}.${TAG}.moderator@${domain}'
ldapmod <<_END
dn: cn=$user $TAG memonly,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: moderator
moderator: ${user}.${TAG}.moderator@${domain}
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - moderated memonly group: member, direct
### ----------------------------------------------

To="${user}.${TAG}.memonly@${domain}"
From="${user}@${domain}"
Name="Member, direct to Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - moderated memonly group: not member, direct
### --------------------------------------------------

To="${user}.${TAG}.memonly@${domain}"
From="${user}.${TAG}.simple${TAG}.simple@${domain}"
Name="Not Member, direct to Moderated+MembersOnly"
Result="Delivered to moderator"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test

### GRID - moderated memonly group: moderator, permitted
### ----------------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}.${TAG}.moderator@${domain}"
Name="Moderator, through Permitted, to Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - moderated memonly group: member, permitted group
### -------------------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}@${domain}"
Name="Member, through Permitted, to Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - moderated memonly group: not member, permitted group
### -----------------------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not member, through Permitted, to Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - moderated memonly group: moderator, not permitted
### --------------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}.${TAG}.moderator@${domain}"
Name="Moderator, through Not Permitted, to Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - moderated memonly group: member, not permitted group
### -----------------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}@${domain}"
Name="Member, through Not Permitted, to Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - moderated memonly group: not member, not permitted group
### ---------------------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not Member, through Not Permitted, to Moderated+MembersOnly"
Result="Delivered to moderator"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


# --------------------------------------------
# Private and Moderated and Members Only group
# --------------------------------------------

### GRID - private moderated memonly group: moderator, direct
### ---------------------------------------------------------

To="${user}.${TAG}.memonly@${domain}"
From="${user}.${TAG}.moderator@${domain}"
Name="Moderator, direct to Private+Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"

## This should already be set, but we'll set it regardless.
# ldap: '$user $TAG memonly' enable moderator
ldapmod <<_END
dn: cn=$user $TAG memonly,ou=User Groups,ou=Groups,dc=umich,dc=edu
changetype: modify
replace: moderator
moderator: ${user}.${TAG}.moderator@${domain}
_END

mail_test	"$From" "$To" "$Name" "$Result"

end_test


### GRID - private moderated memonly group: member, direct
### ------------------------------------------------------

To="${user}.${TAG}.memonly@${domain}"
From="${user}@${domain}"
Name="Member, direct to Private+Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - private moderated memonly group: not member, direct
### ----------------------------------------------------------

To="${user}.${TAG}.memonly@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not Member, direct to Private+Moderated+MembersOnly"
Result="Delivered to moderator"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - private moderated memonly group: moderator,permitted
### ------------------------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}.${TAG}.moderator@${domain}"
Name="Moderator, through Permitted, to Private+Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test

### GRID - private moderated memonly group: member, permitted group
### ---------------------------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}@${domain}"
Name="Member, through Permitted, to Private+Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - private moderated memonly group: member, permitted group
### ---------------------------------------------------------------

To="${user}.${TAG}.permitted@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not member, through Permitted, to Private+Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - private moderated memonly group: moderator, not permitted
### ----------------------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}.${TAG}.moderator@${domain}"
Name="Moderator, through Not Permitted, to Private+Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test

### GRID - private moderated memonly group: member, not permitted group
### -------------------------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}@${domain}"
Name="Member, through Not Permitted, to Private+Moderated+MembersOnly"
Result="Delivered through '$To'"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


### GRID - private moderated memonly group: not member, not permitted group
### -----------------------------------------------------------------------

To="${user}.${TAG}.notpermitted@${domain}"
From="${user}.${TAG}.simple@${domain}"
Name="Not Member, through Not Permitted, to Private+Moderated+MembersOnly"
Result="Delivered to moderator"

begin_test	"$Name" "$Result"
mail_test	"$From" "$To" "$Name" "$Result"
end_test


echo "Testing complete."
echo -n "Cleanup:  "
pause
cleanup

echo "That's all folks!"
echo ""

# EOF
