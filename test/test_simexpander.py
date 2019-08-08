import json
import os
import subprocess

import pytest


SUBADDR_TESTS = [
    '',
    '+',
    '=',
    '+foo',
    '=foo',
    '+foo+bar',
]


@pytest.fixture
def expansion_config(simta_config, request, tmp_path, ldapserver):
    passwd_file = os.path.join(str(tmp_path), 'passwd')
    alias_file = os.path.join(str(tmp_path), 'alias')
    alias_db = os.path.join(str(tmp_path), 'alias.db')
    with open(passwd_file, 'w') as f:
        f.write('testuser:x:1000:1000::{}/testuser:/sbin/nologin\n'.format(str(tmp_path)))
        f.write('forwarduser:x:1001:1001::{}:/sbin/nologin\n'.format(str(tmp_path)))

    with open(os.path.join(str(tmp_path), '.forward'), 'w') as f:
        f.write('user@example.com\n')
        f.write('user@example.edu\n')

    with open(alias_file, 'w') as f:
        f.write('testuser: anotheruser\n')
        f.write('external: testuser@example.edu\n')
        f.write('password: testuser@password.example.com\n')
        f.write('chained: testuser@alias.example.com\n')
        f.write('group: testuser@alias.example.com, groupuser@example.com\n')
        f.write('group2-errors: anotheruser\n')
        f.write('group2: group@alias.example.com\n')

    config = {}
    config['domain'] = {
        'password.example.com': {
            'rule': [
                {
                    'type': 'password',
                    'password': {
                        'path': passwd_file,
                    },
                },
            ]
        },
        'alias.example.com': {
            'rule': [
                {
                    'type': 'alias',
                    'alias': {
                        'path': alias_db,
                    }
                }
            ]
        }
    }

    if 'subaddress' in request.function.__name__:
        config['defaults'] = {
            'red_rule': {
                'expand': {
                    'subaddress_separators': '+='
                }
            }
        }

    if ldapserver['enabled']:
        config['domain']['ldap.example.com'] = {
            'expand': {
                'permit_subdomains': True,
            },
            'rule': [
                {
                    'type': 'ldap',
                    'ldap': {
                        'uri': ldapserver['uri'],
                        'attributes': {
                            'forwarding': 'mailForwardingAddress',
                            'vacation': 'onVacation',
                        },
                        'search': [
                            {
                                'uri': 'ldap:///ou=People,dc=example,dc=com?*?sub?uid=%25s',
                                'type': 'user',
                            },
                            {
                                'uri': 'ldap:///ou=Groups,dc=example,dc=com?*?sub?cn=%25s',
                                'rdnpref': True,
                                'type': 'all',
                            },
                        ],
                        'vacation': {
                            'host': 'vacation.mail.example.com',
                        },
                    },
                }
            ]
        }

    with open(os.path.join(str(tmp_path), 'dynamic.conf'), 'w') as f:
        f.write(json.dumps(config)[1:-1])

    return simta_config


def parse_expander_output(output):
    parsed = []
    unparsed = []
    cur_obj = None
    for line in output.split('\n'):
        if cur_obj == None:
            if line == '{':
                cur_obj = line
            else:
                unparsed.append(line)
        else:
            cur_obj += line
            if line == '}':
                parsed.append(json.loads(cur_obj))
                cur_obj = None
    return {
        'parsed': parsed,
        'unparsed': unparsed,
    }


@pytest.fixture
def run_simexpander(expansion_config, tool_path):
    def _run_simexpander(addresses):
        subprocess.check_output([
            tool_path('simalias'),
            '-f', expansion_config,
        ])

        args = [
            tool_path('simexpander'),
            '-f', expansion_config,
        ]
        if isinstance(addresses, list):
            args.extend(addresses)
        else:
            args.append(addresses)

        return parse_expander_output(subprocess.check_output(args))
    return _run_simexpander


def test_expand_none(run_simexpander):
    res = run_simexpander('testuser@none.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@none.example.com' ]


def test_expand_password(run_simexpander):
    res = run_simexpander('testuser@password.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@password.example.com' ]


def assert_nonexist(res):
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'sender@expansion.test' ]
    assert res['parsed'][0]['sender'] == ''
    assert any('address not found: ' in line for line in res['unparsed'])


def test_expand_password_nonexist(run_simexpander):
    assert_nonexist(run_simexpander('baduser@password.example.com'))


def test_expand_password_forward(run_simexpander):
    res = run_simexpander('forwarduser@password.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == [ 'user@example.com' ]
    assert res['parsed'][1]['recipients'] == [ 'user@example.edu' ]


def test_expand_alias(run_simexpander):
    res = run_simexpander('testuser@alias.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'anotheruser@masquerade.example.com' ]


def test_expand_alias_nonexist(run_simexpander):
    assert_nonexist(run_simexpander('baduser@alias.example.com'))


@pytest.mark.parametrize('slug', SUBADDR_TESTS)
def test_expand_alias_subaddress(run_simexpander, slug):
    res = run_simexpander('testuser{}@alias.example.com'.format(slug))
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'anotheruser@masquerade.example.com' ]


def test_expand_alias_subaddress_nonexist(run_simexpander):
    assert_nonexist(run_simexpander('testuser_foo@alias.example.com'))


def test_expand_alias_external(run_simexpander):
    res = run_simexpander('external@alias.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@example.edu' ]


def test_expand_alias_password(run_simexpander):
    res = run_simexpander('password@alias.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@password.example.com' ]


def test_expand_alias_chained(run_simexpander):
    res = run_simexpander('chained@alias.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'anotheruser@masquerade.example.com' ]


def test_expand_alias_group(run_simexpander):
    res = run_simexpander('group@alias.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == [ 'groupuser@example.com' ]
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'
    assert res['parsed'][1]['recipients'] == [ 'anotheruser@masquerade.example.com' ]
    assert res['parsed'][1]['sender'] == 'sender@expansion.test'


def test_expand_alias_group_errorsto(run_simexpander):
    res = run_simexpander('group2@alias.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == [ 'groupuser@example.com' ]
    assert res['parsed'][0]['sender'] == 'group2-errors@alias.example.com'
    assert res['parsed'][1]['recipients'] == [ 'anotheruser@masquerade.example.com' ]
    assert res['parsed'][1]['sender'] == 'group2-errors@alias.example.com'


def test_expand_ldap_user_nonexist(run_simexpander, req_ldapserver):
    assert_nonexist(run_simexpander('baduser@ldap.example.com'))


def test_expand_ldap_user(run_simexpander, req_ldapserver):
    res = run_simexpander('testuser@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@forwarded.example.com' ]
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'


@pytest.mark.parametrize('slug', SUBADDR_TESTS)
def test_expand_ldap_subaddress(run_simexpander, req_ldapserver, slug):
    res = run_simexpander('testuser{}@ldap.example.com'.format(slug))
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@forwarded.example.com' ]
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'


def test_expand_ldap_subaddress_nonexist(run_simexpander, req_ldapserver):
    assert_nonexist(run_simexpander('testuser_foo@alias.example.com'))


def test_expand_ldap_group(run_simexpander, req_ldapserver):
    res = run_simexpander('testgroup@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@forwarded.example.com' ]
    assert res['parsed'][0]['sender'] == 'testgroup-errors@ldap.example.com'


@pytest.mark.parametrize('slug', [
    'errors',
    'error',
    'requests',
    'request',
    'owners',
    'owner',
])
def test_expand_ldap_group_owners(run_simexpander, req_ldapserver, slug):
    res = run_simexpander('testgroup-{}@ldap.example.com'.format(slug))
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@forwarded.example.com' ]
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'


@pytest.mark.parametrize('slug', [
    'errors',
    'requests',
])
def test_expand_ldap_group_FOOto(run_simexpander, req_ldapserver, slug):
    res = run_simexpander('testgroup.nonowner-{}@ldap.example.com'.format(slug))
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == [ '{}to@forwarded.example.com'.format(slug) ]
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'
    assert res['parsed'][1]['recipients'] == [ '{}to@example.edu'.format(slug) ]
    assert res['parsed'][1]['sender'] == 'sender@expansion.test'


@pytest.mark.parametrize('sender', [
    'simexpand@ldap.example.com',
    'simexpand@subdomain.ldap.example.com',
    'prvs=4068eb2540=simexpand@ldap.example.com',       # BATV
    'btv1==068a4973b3a==simexpand@ldap.example.com',    # Barracuda
    # FIXME: SRS? subaddressing?
])
def test_expand_ldap_group_membersonly(run_simexpander, req_ldapserver, sender):
    res = run_simexpander([
        '-F', sender,
        'membersonly.succeed@ldap.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'simexpand@forwarded.example.com' ]
    assert res['parsed'][0]['sender'] == 'membersonly.succeed-errors@ldap.example.com'


def test_expand_ldap_group_membersonly_no(run_simexpander, req_ldapserver):
    res = run_simexpander('membersonly.fail@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'sender@expansion.test' ]
    assert res['parsed'][0]['sender'] == ''
    assert any('Members only group conditions not met: ' in line for line in res['unparsed'])


def test_expand_ldap_group_membersonly_permitted(run_simexpander, req_ldapserver):
    res = run_simexpander('public.supergroup@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@forwarded.example.com' ]


def test_expand_ldap_group_nested(run_simexpander, req_ldapserver):
    res = run_simexpander('nested.group.1@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@forwarded.example.com' ]
    assert res['parsed'][0]['sender'] == 'nested.group.3-errors@ldap.example.com'


def test_expand_ldap_group_recursive(run_simexpander, req_ldapserver):
    res = run_simexpander('loop.group.1@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@forwarded.example.com' ]
    assert res['parsed'][0]['sender'] == 'loop.group.1-errors@ldap.example.com'


@pytest.mark.parametrize('sender', [
    'simexpand@ldap.example.com',
    'simexpand@subdomain.ldap.example.com',
    'prvs=4068eb2540=simexpand@ldap.example.com',       # BATV
    'btv1==068a4973b3a==simexpand@ldap.example.com',    # Barracuda
    # FIXME: SRS?
])
def test_expand_ldap_group_moderated(run_simexpander, req_ldapserver, sender):
    res = run_simexpander([
        '-F', sender,
        'moderated.group@ldap.example.com',
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@forwarded.example.com' ]
    assert res['parsed'][0]['sender'] == 'moderated.group-errors@ldap.example.com'


@pytest.mark.parametrize('sender',
    [
        'simexpand@example.com',
        'simexpand@notldap.example.com',
        'simexpand@example.edu',
    ]
)
@pytest.mark.parametrize('target',
    [
        'moderated.group@ldap.example.com',
        'mo.moderated.group@ldap.example.com',
    ]
)
def test_expand_ldap_group_moderated_nonmod(run_simexpander, req_ldapserver, sender, target):
    res = run_simexpander([
        '-F', sender,
        target,
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'simexpand@ldap.example.com' ]
    assert res['parsed'][0]['sender'] == sender


@pytest.mark.parametrize('sender', [
    'simexpand@ldap.example.com',           # moderator
    'simexpand@subdomain.ldap.example.com', # mod permitted subdomain match
    'testuser@ldap.example.com',            # member email
    'testuser@forwarded.example.com',       # member forwarding address
    'testuser@subdomain.ldap.example.com',  # member permitted subdomain match
])
def test_expand_ldap_group_moderated_membersonly(run_simexpander, req_ldapserver, sender):
    res = run_simexpander([
        '-F', sender,
        'mo.moderated.group@ldap.example.com',
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'testuser@forwarded.example.com' ]
    assert res['parsed'][0]['sender'] == 'mo.moderated.group-errors@ldap.example.com'
    assert not any('Members only group conditions not met: ' in line for line in res['unparsed'])


#test_expand_ldap_group_moderated_membersonly_permitted
#test_expand_ldap_group_moderated_badmoderator (unparsable address, somehow?)
#test_expand_ldap_group_moderated_modloop
#test_expand_ldap_group_moderated_subgroup
#test_expand_ldap_group_moderated_nopermitsub


def test_expand_ldap_user_vacation(run_simexpander, req_ldapserver):
    res = run_simexpander('onvacation@ldap.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == [ 'onvacation@forwarded.example.com' ]
    assert res['parsed'][1]['recipients'] == [ 'onvacation@vacation.mail.example.com' ]


def test_expand_ldap_group_vacation(run_simexpander, req_ldapserver):
    res = run_simexpander('vacation.group@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [ 'vacation.group@vacation.mail.example.com' ]
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'


#test_expand_ldap_group_member_nomfa
#test_expand_ldap_group_member_nomfa_suppress

#test_expand_ldap_quotedlocalpart
#test_expand_ldap_ambiguous
#test_expand_ldap_precedence
#test_expand_ldap_danglingref (e.g. member: points to nonexistent entry)

#test_expand_ldap_group_associated_domain

#LDAP rfc822mail tests

#test_expand_srs
#test_expand_srs_reforwarded
#test_expand_srs_expired
#test_expand_srs_invalid
