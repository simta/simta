#!/usr/bin/env python3

import sys


def print_user(fn, sn):
    uid = fn + sn
    print('dn: uid={},ou=People,dc=example,dc=com'.format(uid))
    print('objectClass: umichPerson')
    print('cn: {} {}'.format(fn, sn))
    print('sn: {}'.format(sn))
    print('mail: {}@example.com'.format(uid))
    print('uid: {}'.format(uid))
    print('mailForwardingAddress: {}@forwarded.example.com'.format(uid))
    print('entityID: 90001')
    print('')


print()
slug = sys.argv[1]
fn = slug.replace(' ', '-')
for sn in ['owner', 'member0', 'member1']:
    print_user(fn, sn)

print('dn: cn={},ou=Groups,dc=example,dc=com'.format(slug))
print('objectClass: rfc822mailgroup')
print('owner: uid={}owner,ou=People,dc=example,dc=com'.format(fn))
print('member: uid={}member0,ou=People,dc=example,dc=com'.format(fn))
print('member: uid={}member1,ou=People,dc=example,dc=com'.format(fn))
