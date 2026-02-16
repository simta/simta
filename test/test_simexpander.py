#!/usr/bin/env python3

import json
import subprocess

import pytest

from dirty_equals import IsStr
from inline_snapshot import snapshot, Is


SUBADDR_TESTS = [
    '',
    '+',
    '=',
    '+foo',
    '=foo',
    '+foo+bar',
]


IsEnvelopeId = IsStr(regex=r'[0-9A-F]{8}\.[0-9A-F]{1,8}\.[0-9A-F]{1,8}\.[0-9]+')
# FIXME: it would be better to figure out the correct hostname
IsMailerDaemon = IsStr(regex=r'mailer-daemon@.+')


def parse_expander_output(output):
    parsed = []
    unparsed = []
    cur_obj = None
    for line in output.splitlines():
        if cur_obj is None:
            if line == '{':
                cur_obj = line
            elif line:
                unparsed.append(line)
        else:
            cur_obj += line
            if line == '}':
                parsed.append(json.loads(cur_obj))
                cur_obj = None

    # Basic correctness check
    for env in parsed:
        if env.get('hostname'):
            assert len(env['recipients']) == 1
            assert env['recipients'][0].endswith(env['hostname'])

    # output ordering is an implementation detail, sort so that tests have
    # a more stable view.
    parsed = sorted(parsed, key=lambda x: (x['sender'], x['recipients']))
    return {
        'parsed': parsed,
        'unparsed': unparsed,
    }


def assert_sender(res, sender='sender@expansion.test'):
    assert all(x['sender'] == sender for x in res['parsed'])


@pytest.fixture
def run_simexpander(expansion_config, tool_path):
    def _run_simexpander(addresses):
        subprocess.run(
            [
                tool_path('simalias'),
                '-f',
                expansion_config,
            ],
            check=True,
        )

        args = [
            tool_path('simexpander'),
            '-f',
            expansion_config,
        ]
        if isinstance(addresses, list):
            args.extend(addresses)
        else:
            args.append(addresses)

        return parse_expander_output(subprocess.run(args, check=True, capture_output=True, text=True).stdout)

    return _run_simexpander


def test_expand_none(run_simexpander):
    assert run_simexpander('testuser@none.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'none.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@none.example.com'],
                }
            ],
            'unparsed': ['Original Recipient: testuser@none.example.com', 'Terminal: testuser@none.example.com'],
        }
    )


def test_expand_quotes(run_simexpander):
    assert run_simexpander(
        [
            '-F',
            '"."@example.com',
            '"testuser with spaces"@none.example.com',
        ]
    ) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'none.example.com',
                    'sender': '"."@example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': '"."@example.com',
                    'recipients': ['"testuser with spaces"@none.example.com'],
                }
            ],
            'unparsed': ['Original Recipient: "testuser with spaces"@none.example.com', 'Terminal: "testuser with spaces"@none.example.com'],
        }
    )


def test_expand_password(run_simexpander):
    assert run_simexpander('testuser@password.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'password.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@password.example.com'],
                }
            ],
            'unparsed': ['Original Recipient: testuser@password.example.com', 'Terminal: testuser@password.example.com'],
        }
    )


def test_expand_password_nonexist(run_simexpander):
    assert run_simexpander('baduser@password.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': ['address not found: baduser@password.example.com'],
                }
            ],
            'unparsed': ['Original Recipient: baduser@password.example.com', 'Non-terminal: baduser@password.example.com'],
        }
    )


def test_expand_password_forward(run_simexpander):
    assert run_simexpander('forwarduser@password.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['user@example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['user@example.edu'],
                },
            ],
            'unparsed': [
                'Original Recipient: forwarduser@password.example.com',
                'Non-terminal: forwarduser@password.example.com',
                'Terminal: user@example.edu',
                'Terminal: user@example.com',
            ],
        }
    )


def test_expand_alias(run_simexpander):
    assert run_simexpander('testuser@alias.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'masquerade.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['anotheruser@masquerade.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: testuser@alias.example.com',
                'Non-terminal: testuser@alias.example.com',
                'Terminal: anotheruser@masquerade.example.com',
            ],
        }
    )


def test_expand_alias_nonexist(run_simexpander):
    assert run_simexpander('baduser@alias.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': ['address not found: baduser@alias.example.com'],
                }
            ],
            'unparsed': ['Original Recipient: baduser@alias.example.com', 'Non-terminal: baduser@alias.example.com'],
        }
    )


@pytest.mark.parametrize('slug', SUBADDR_TESTS)
def test_expand_alias_subaddress(run_simexpander, slug):
    assert run_simexpander(f'testuser{slug}@alias.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'masquerade.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['anotheruser@masquerade.example.com'],
                }
            ],
            'unparsed': [
                Is(f'Original Recipient: testuser{slug}@alias.example.com'),
                Is(f'Non-terminal: testuser{slug}@alias.example.com'),
                'Terminal: anotheruser@masquerade.example.com',
            ],
        }
    )


def test_expand_alias_subaddress_nonexist(run_simexpander):
    assert run_simexpander('testuser_foo@alias.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': ['address not found: testuser_foo@alias.example.com'],
                }
            ],
            'unparsed': ['Original Recipient: testuser_foo@alias.example.com', 'Non-terminal: testuser_foo@alias.example.com'],
        }
    )


def test_expand_alias_external(run_simexpander):
    assert run_simexpander('external@alias.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@example.edu'],
                }
            ],
            'unparsed': ['Original Recipient: external@alias.example.com', 'Non-terminal: external@alias.example.com', 'Terminal: testuser@example.edu'],
        }
    )


def test_expand_alias_password(run_simexpander):
    assert run_simexpander('password@alias.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'password.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@password.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: password@alias.example.com',
                'Non-terminal: password@alias.example.com',
                'Terminal: testuser@password.example.com',
            ],
        }
    )


def test_expand_alias_chained(run_simexpander):
    assert run_simexpander('chained@alias.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'masquerade.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['anotheruser@masquerade.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: chained@alias.example.com',
                'Non-terminal: chained@alias.example.com',
                'Non-terminal: testuser@alias.example.com',
                'Terminal: anotheruser@masquerade.example.com',
            ],
        }
    )


def test_expand_alias_group(run_simexpander):
    assert run_simexpander('group@alias.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'masquerade.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['anotheruser@masquerade.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['groupuser@example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: group@alias.example.com',
                'Non-terminal: group@alias.example.com',
                'Non-terminal: testuser@alias.example.com',
                'Terminal: anotheruser@masquerade.example.com',
                'Terminal: groupuser@example.com',
            ],
        }
    )


def test_expand_alias_group_errorsto(run_simexpander):
    assert run_simexpander('group2@alias.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'masquerade.example.com',
                    'sender': 'group2-errors@alias.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['anotheruser@masquerade.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.com',
                    'sender': 'group2-errors@alias.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['groupuser@example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: group2@alias.example.com',
                'Non-terminal: group2@alias.example.com',
                'Non-terminal: group@alias.example.com',
                'Non-terminal: testuser@alias.example.com',
                'Terminal: anotheruser@masquerade.example.com',
                'Terminal: groupuser@example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'target',
    [
        'group2-errors@alias.example.com',
        'owner-group2@alias.example.com',
        'group2-owners@alias.example.com',
        'group2-error@alias.example.com',
        'group2-requests@alias.example.com',
        'group2-errors@alias.example.com',
    ],
)
def test_expand_alias_group_errors(run_simexpander, target):
    assert run_simexpander(target) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'masquerade.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['anotheruser@masquerade.example.com'],
                }
            ],
            'unparsed': [IsStr(regex='Original Recipient: .+'), IsStr(regex='Non-terminal: .+'), 'Terminal: anotheruser@masquerade.example.com'],
        }
    )


def test_expand_srs(run_simexpander, run_simsrs):
    addr = 'testsender@example.edu'
    srs = run_simsrs(addr)
    assert run_simexpander(srs) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testsender@example.edu'],
                }
            ],
            'unparsed': [f'Original Recipient: {srs}', f'Non-terminal: {srs}', 'Terminal: testsender@example.edu'],
        }
    )


def test_expand_ldap_user_nonexist(run_simexpander, req_ldapserver):
    assert run_simexpander('baduser@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': ['address not found: baduser@ldap.example.com'],
                }
            ],
            'unparsed': ['Original Recipient: baduser@ldap.example.com', 'Non-terminal: baduser@ldap.example.com'],
        }
    )


def test_expand_ldap_user(run_simexpander, req_ldapserver):
    assert run_simexpander('testuser@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: testuser@ldap.example.com',
                'Non-terminal: testuser@ldap.example.com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize('slug', SUBADDR_TESTS)
def test_expand_ldap_subaddress(run_simexpander, req_ldapserver, slug):
    assert run_simexpander(f'testuser{slug}@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                Is(f'Original Recipient: testuser{slug}@ldap.example.com'),
                Is(f'Non-terminal: testuser{slug}@ldap.example.com'),
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_subaddress_nonexist(run_simexpander, req_ldapserver):
    assert run_simexpander('testuser_foo@alias.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': ['address not found: testuser_foo@alias.example.com'],
                }
            ],
            'unparsed': ['Original Recipient: testuser_foo@alias.example.com', 'Non-terminal: testuser_foo@alias.example.com'],
        }
    )


@pytest.mark.parametrize(
    'target',
    [
        'testgroup@ldap.example.com',
        'testgroup.alias@ldap.example.com',
        'testgroup_alias@ldap.example.com',
        "testgroup.*.!#$%&-/=?^_`{|}~'+@ldap.example.com",
        '"testgroup alias"@ldap.example.com',
        '"testgroup.alias"@ldap.example.com',
        '"testgroup_alias"@ldap.example.com',
        '"testgroup"@ldap.example.com',
        '"testgroup\\ alias"@ldap.example.com',
        '"testgroup(*)"@ldap.example.com',
        '"testgroup * (!#$%&-/=?^_`{|}~\'+)"@ldap.example.com',
    ],
)
def test_expand_ldap_group(run_simexpander, req_ldapserver, target):
    assert run_simexpander(target) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'testgroup-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                Is(f'Original Recipient: {target}'),
                Is(f'Non-terminal: {target}'),
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'slug',
    [
        'errors',
        'error',
        'requests',
        'request',
        'owners',
        'owner',
    ],
)
def test_expand_ldap_group_owners(run_simexpander, req_ldapserver, slug):
    assert run_simexpander(f'testgroup-{slug}@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                Is(f'Original Recipient: testgroup-{slug}@ldap.example.com'),
                Is(f'Non-terminal: testgroup-{slug}@ldap.example.com'),
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'slug',
    [
        'errors',
        'requests',
    ],
)
def test_expand_ldap_group_FOOto(run_simexpander, req_ldapserver, slug):
    assert run_simexpander(f'testgroup.nonowner-{slug}@ldap.example.com')['parsed'] == snapshot(
        [
            {
                'envelope_id': IsEnvelopeId,
                'body_inode': 0,
                'expansion_level': 1,
                'hostname': 'example.edu',
                'sender': 'sender@expansion.test',
                '8bitmime': False,
                'jailed': False,
                'bounceable': True,
                'puntable': True,
                'original_sender': 'sender@expansion.test',
                'recipients': [Is(f'{slug}to@example.edu')],
            },
            {
                'envelope_id': IsEnvelopeId,
                'body_inode': 0,
                'expansion_level': 1,
                'hostname': 'forwarded.example.com',
                'sender': 'sender@expansion.test',
                '8bitmime': False,
                'jailed': False,
                'bounceable': True,
                'puntable': True,
                'original_sender': 'sender@expansion.test',
                'recipients': [Is(f'{slug}to@forwarded.example.com')],
            },
        ]
    )


def test_expand_ldap_group_weird_spacing(run_simexpander, req_ldapserver):
    assert run_simexpander('_testgroup__weird___spacing____issue_@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': '_testgroup._weird._.spacing._._issue_-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: _testgroup__weird___spacing____issue_@ldap.example.com',
                'Non-terminal: _testgroup__weird___spacing____issue_@ldap.example.com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_empty(run_simexpander, req_ldapserver):
    assert run_simexpander('testgroup.empty@ldap.example.com') == snapshot(
        {'parsed': [], 'unparsed': ['Original Recipient: testgroup.empty@ldap.example.com', 'Non-terminal: testgroup.empty@ldap.example.com']}
    )


@pytest.mark.parametrize(
    'sender',
    [
        'simexpand@ldap.example.com',
        'SIMEXPAND@LDAP.EXAMPLE.COM',
        'SIMEXPAND@EXAMPLE.COM',
        'SIMEXPAND@P.EXAMPLE.COM',
        'simexpand@example.com',
        'simexpand@dap.example.com',
        'simexpand@p.example.com',
        'simexpand@notldap.example.com',
        'simexpand@nomatch.example.com',
        'simexpand@subdomain.ldap.example.com',
        'simexpand@subdomain.dap.example.com',
        'simexpand@subdomain.p.example.com',
        'simexpand@subdomain.notldap.example.com',
        'simexpand@subdomain.nomatch.example.com',
        'prvs=4068eb2540=simexpand@ldap.example.com',  # BATV
        'btv1==068a4973b3a==simexpand@ldap.example.com',  # Barracuda
        # FIXME: SRS? subaddressing?
    ],
)
def test_expand_ldap_group_membersonly(run_simexpander, req_ldapserver, sender):
    assert run_simexpander(['-F', sender, 'membersonly.succeed@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'membersonly.succeed-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': ['simexpand@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: membersonly.succeed@ldap.example.com',
                'Non-terminal: membersonly.succeed@ldap.example.com',
                'Non-terminal: uid=simexpand,ou=people,dc=example,dc=com',
                'Terminal: simexpand@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'sender',
    [
        'simexpant@ldap.example.com',
        'timexpand@ldap.example.com',
        'simexpander@ldap.example.com',
        'expand@ldap.example.com',
        'd@ldap.example.com',
        'ssimexpand@ldap.example.com',
        'simexpand@dexample.com',
        'simexpand@xample.com',
        'simexpand@s.xample.com',
        'simexpand@s.ample.com',
        'simexpand@e.com',
        'simexpand@s.e.com',
        'simexpand@notexample.com',
        'simexpand@nomatch.com',
        'simexpand@example.edu',
        'prvs=4068eb2540=simexpand@example.edu',
        'btv1==068a4973b3a==simexpand@notexample.com',
    ],
)
def test_expand_ldap_group_membersonly_nonmember(run_simexpander, req_ldapserver, sender):
    assert run_simexpander(['-F', sender, 'membersonly.succeed@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': [Is(sender)],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: membersonly.succeed@ldap.example.com',
                        'If you have any questions, please contact the group owner: membersonly.succeed-owner@ldap.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: membersonly.succeed@ldap.example.com',
                'Suppressed: uid=simexpand,ou=people,dc=example,dc=com',
                'Suppressed: simexpand@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_membersonly_no(run_simexpander, req_ldapserver):
    assert run_simexpander('membersonly.fail@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: membersonly.fail@ldap.example.com',
                        'If you have any questions, please contact the group owner: membersonly.fail-owner@ldap.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: membersonly.fail@ldap.example.com',
                'Suppressed: uid=testuser,ou=people,dc=example,dc=com',
                'Suppressed: testuser@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_membersonly_permitted(run_simexpander, req_ldapserver):
    assert run_simexpander('public.supergroup@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'membersonly.subgroup-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: public.supergroup@ldap.example.com',
                'Non-terminal: public.supergroup@ldap.example.com',
                'Non-terminal: cn=membersonly subgroup,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_membersonly_recursive(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'simexpand@ldap.example.com', 'membersonly.recurse@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'membersonly.recurse.subgroup-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'simexpand@ldap.example.com',
                    'recipients': ['simexpand@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: membersonly.recurse@ldap.example.com',
                'Non-terminal: membersonly.recurse@ldap.example.com',
                'Non-terminal: cn=membersonly recurse subgroup,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=simexpand,ou=people,dc=example,dc=com',
                'Terminal: simexpand@forwarded.example.com',
            ],
        }
    )


# FIXME: if a subgroup is private, no membersonly bounce should be created
# if membership is public, the bounce should go to the owners of the containing
# group.


def test_expand_ldap_group_nested(run_simexpander, req_ldapserver):
    assert run_simexpander('nested.group.1@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'nested.group.3-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: nested.group.1@ldap.example.com',
                'Non-terminal: nested.group.1@ldap.example.com',
                'Non-terminal: cn=nested group 2,ou=groups,dc=example,dc=com',
                'Non-terminal: cn=nested group 3,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_recursive(run_simexpander, req_ldapserver):
    assert run_simexpander('loop.group.1@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'loop.group.1-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: loop.group.1@ldap.example.com',
                'Non-terminal: loop.group.1@ldap.example.com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
                'Non-terminal: cn=loop group 2,ou=groups,dc=example,dc=com',
                'Non-terminal: cn=loop group 1,ou=groups,dc=example,dc=com',
            ],
        }
    )


@pytest.mark.parametrize(
    'sender',
    [
        'simexpand@example.com',
        'simexpand@ldap.example.com',
        'simexpand@dap.example.com',
        'simexpand@notldap.example.com',
        'simexpand@nomatch.example.com',
        'simexpand@subdomain.ldap.example.com',
        'simexpand@subdomain.dap.example.com',
        'simexpand@subdomain.notldap.example.com',
        'simexpand@subdomain.nomatch.example.com',
        'prvs=4068eb2540=simexpand@ldap.example.com',  # BATV
        'btv1==068a4973b3a==simexpand@ldap.example.com',  # Barracuda
        # FIXME: SRS?
    ],
)
def test_expand_ldap_group_moderated(run_simexpander, req_ldapserver, sender):
    assert run_simexpander(['-F', sender, 'moderated.group@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'moderated.group-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: moderated.group@ldap.example.com',
                'Non-terminal: moderated.group@ldap.example.com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'sender',
    [
        'simexpan@ldap.example.com',
        'simexpander@ldap.example.com',
        'notsimexpand@ldap.example.com',
        'nomatch@ldap.example.com',
        'simexpan@example.com',
        'simexpander@example.com',
        'notsimexpand@example.com',
        'nomatch@example.com',
        'simexpand@xample.com',
        'simexpand@notexample.com',
        'simexpand@nomatch.com',
        'simexpand@example.edu',
    ],
)
@pytest.mark.parametrize(
    'target',
    [
        'moderated.group',
        'mo.moderated.group',
    ],
)
def test_expand_ldap_group_moderated_nonmod(run_simexpander, req_ldapserver, sender, target):
    assert run_simexpander(['-F', sender, f'{target}@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': Is(f'{target}-errors@ldap.example.com'),
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'header_from': Is(f'{target}@ldap.example.com'),
                    'recipients': ['simexpand@ldap.example.com'],
                }
            ],
            'unparsed': [
                Is(f'Original Recipient: {target}@ldap.example.com'),
                Is(f'Moderated: {target}@ldap.example.com'),
                'Suppressed: uid=testuser,ou=people,dc=example,dc=com',
                'Suppressed: testuser@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'sender',
    [
        'simexpand@ldap.example.com',  # moderator
        'simexpand@subdomain.ldap.example.com',  # mod permitted subdomain match
        'simexpand@example.com',  # mod permitted subdomain match
        'simexpand@notldap.example.com',  # mod permitted subdomain match
        'simexpand@nomatch.example.com',  # mod permitted subdomain match
        'simexpand@subdomain.notldap.example.com',  # mod permitted subdomain match
        'testuser@ldap.example.com',  # member email
        'testuser@forwarded.example.com',  # member forwarding address
        'testuser@subdomain.ldap.example.com',  # member permitted subdomain match
    ],
)
def test_expand_ldap_group_moderated_membersonly(run_simexpander, req_ldapserver, sender):
    assert run_simexpander(['-F', sender, 'mo.moderated.group@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'mo.moderated.group-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: mo.moderated.group@ldap.example.com',
                'Non-terminal: mo.moderated.group@ldap.example.com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_moderated_badmoderator(run_simexpander, req_ldapserver):
    assert run_simexpander(['bad.moderated.group@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['bad.moderated.group-errors@ldap.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'bad permitted senders: cn=bad moderated group,ou=groups,dc=example,dc=com',
                        'bad moderators: cn=bad moderated group,ou=groups,dc=example,dc=com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: bad.moderated.group@ldap.example.com',
                        'If you have any questions, please contact the group owner: bad.moderated.group-owner@ldap.example.com',
                    ],
                },
            ],
            'unparsed': [
                'Original Recipient: bad.moderated.group@ldap.example.com',
                'Suppressed: uid=testuser,ou=people,dc=example,dc=com',
                'Suppressed: testuser@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'sender',
    [
        'testuser@ldap.example.com',  # subgroup member
        'sender@expansion.test',  # random non-member
        'simexpand@ldap.example.com',  # subgroup moderator
    ],
)
def test_expand_ldap_group_moderated_membersonly_permitted(run_simexpander, req_ldapserver, sender):
    assert run_simexpander(['-F', sender, 'mo.moderated.public.supergroup@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'mo.moderated.subgroup-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: mo.moderated.public.supergroup@ldap.example.com',
                'Non-terminal: mo.moderated.public.supergroup@ldap.example.com',
                'Non-terminal: cn=mo moderated subgroup,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'sender',
    [
        'testuser@ldap.example.com',  # subgroup member
        'simexpand@ldap.example.com',  # subgroup moderator
    ],
)
def test_expand_ldap_group_moderated_membersonly_nonpermitted_succeed(run_simexpander, req_ldapserver, sender):
    assert run_simexpander(['-F', sender, 'mo.moderated.public.nonpermitted@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'mo.moderated.subgroup-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: mo.moderated.public.nonpermitted@ldap.example.com',
                'Non-terminal: mo.moderated.public.nonpermitted@ldap.example.com',
                'Non-terminal: cn=mo moderated subgroup,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_moderated_membersonly_nonpermitted(run_simexpander, req_ldapserver):
    assert run_simexpander('mo.moderated.public.nonpermitted@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'mo.moderated.subgroup-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'mo.moderated.subgroup@ldap.example.com',
                    'recipients': ['simexpand@ldap.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: mo.moderated.public.nonpermitted@ldap.example.com',
                'Non-terminal: mo.moderated.public.nonpermitted@ldap.example.com',
                'Moderated: cn=mo moderated subgroup,ou=groups,dc=example,dc=com',
                'Suppressed: uid=testuser,ou=people,dc=example,dc=com',
                'Suppressed: testuser@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'sender',
    [
        'testuser@example.edu',
        'otheruser@sub.example.edu',
    ],
)
def test_expand_ldap_group_permitted_domain(run_simexpander, req_ldapserver, sender):
    assert run_simexpander(['-F', sender, 'permitted.domain@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'permitted.domain-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: permitted.domain@ldap.example.com',
                'Non-terminal: permitted.domain@ldap.example.com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'sender',
    [
        'testuser@example.com',
        'testuser@notexample.edu',
        'anotheruser@texample.edu',
        'also@xample.edu',
    ],
)
def test_expand_ldap_group_permitted_domain_fail(run_simexpander, req_ldapserver, sender):
    assert run_simexpander(['-F', sender, 'permitted.domain@ldap.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': [Is(sender)],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: permitted.domain@ldap.example.com',
                        'If you have any questions, please contact the group owner: permitted.domain-owner@ldap.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: permitted.domain@ldap.example.com',
                'Suppressed: uid=testuser,ou=people,dc=example,dc=com',
                'Suppressed: testuser@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_user_vacation(run_simexpander, req_ldapserver):
    assert run_simexpander('onvacation@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['onvacation@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'vacation.mail.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['onvacation@vacation.mail.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: onvacation@ldap.example.com',
                'Non-terminal: onvacation@ldap.example.com',
                'Terminal: onvacation@vacation.mail.example.com',
                'Terminal: onvacation@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_user_autoreply(run_simexpander, req_ldapserver):
    assert run_simexpander('autoreply@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['autoreply@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'vacation.mail.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['autoreply@vacation.mail.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: autoreply@ldap.example.com',
                'Non-terminal: autoreply@ldap.example.com',
                'Terminal: autoreply@vacation.mail.example.com',
                'Terminal: autoreply@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_user_autoreply_past(run_simexpander, req_ldapserver):
    assert run_simexpander('autoreplypast@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['autoreply@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: autoreplypast@ldap.example.com',
                'Non-terminal: autoreplypast@ldap.example.com',
                'Terminal: autoreply@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_user_autoreply_future_end(run_simexpander, req_ldapserver):
    assert run_simexpander('autoreplyend@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['autoreply@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'vacation.mail.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['autoreplyend@vacation.mail.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: autoreplyend@ldap.example.com',
                'Non-terminal: autoreplyend@ldap.example.com',
                'Terminal: autoreplyend@vacation.mail.example.com',
                'Terminal: autoreply@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_user_autoreply_no_start(run_simexpander, req_ldapserver):
    assert run_simexpander('autoreplynostart@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['autoreply@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: autoreplynostart@ldap.example.com',
                'Non-terminal: autoreplynostart@ldap.example.com',
                'Terminal: autoreply@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_user_autoreply_future_start(run_simexpander, req_ldapserver):
    assert run_simexpander('autoreplyfuturestart@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['autoreply@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: autoreplyfuturestart@ldap.example.com',
                'Non-terminal: autoreplyfuturestart@ldap.example.com',
                'Terminal: autoreply@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_user_autoreply_future(run_simexpander, req_ldapserver):
    assert run_simexpander('autoreplyfuture@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['autoreply@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: autoreplyfuture@ldap.example.com',
                'Non-terminal: autoreplyfuture@ldap.example.com',
                'Terminal: autoreply@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_autoreply(run_simexpander, req_ldapserver):
    assert run_simexpander('vacation.group@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'vacation.mail.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['vacation.group@vacation.mail.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: vacation.group@ldap.example.com',
                'Non-terminal: vacation.group@ldap.example.com',
                'Terminal: vacation.group@vacation.mail.example.com',
            ],
        }
    )


def test_expand_ldap_group_member_nomfa(run_simexpander, req_ldapserver):
    assert run_simexpander('nomfa@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['nomfa-errors@ldap.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': ['uid=flowerysong,ou=people,dc=example,dc=com : Group member exists but does not have a valid email forwarding address.\n'],
                }
            ],
            'unparsed': [
                'Original Recipient: nomfa@ldap.example.com',
                'Non-terminal: nomfa@ldap.example.com',
                'Non-terminal: uid=flowerysong,ou=people,dc=example,dc=com',
            ],
        }
    )


def test_expand_ldap_group_member_invalidmfa(run_simexpander, req_ldapserver):
    assert run_simexpander('invalidmfa.group@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['invalidmfa.group-errors@ldap.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': ['uid=invalidmfa,ou=people,dc=example,dc=com : Group member exists but does not have a valid email forwarding address.\n'],
                }
            ],
            'unparsed': [
                'Original Recipient: invalidmfa.group@ldap.example.com',
                'Non-terminal: invalidmfa.group@ldap.example.com',
                'Non-terminal: uid=invalidmfa,ou=people,dc=example,dc=com',
            ],
        }
    )


@pytest.mark.parametrize(
    'target',
    [
        'nomfa.suppress@ldap.example.com',
        'invalidmfa.suppress@ldap.example.com',
    ],
)
def test_expand_ldap_group_member_nomfa_suppress(run_simexpander, req_ldapserver, target):
    assert run_simexpander(target) == snapshot(
        {
            'parsed': [],
            'unparsed': [
                Is(f'Original Recipient: {target}'),
                Is(f'Non-terminal: {target}'),
                IsStr(regex=r'Non-terminal: uid=.+,ou=people,dc=example,dc=com'),
            ],
        }
    )


@pytest.mark.parametrize(
    'target,bounce',
    [
        [
            'flowerysong@ldap.example.com',
            snapshot(
                [
                    'flowerysong: User does not have a valid email forwarding address.\n',
                    '\tName, title, postal address and phone for: flowerysong',
                    '\tflowerysong',
                    '\tDogsbody',
                    '\tBaldrick',
                    '\tInformation and Technology Services ',
                    '\t 4251 Plymouth Rd AL Bldg3 Rm 2320 ',
                    '\t Ann Arbor MI 48105-3640',
                    '\t734-555-1234',
                ]
            ),
        ],
        [
            'gnosyrewolf@ldap.example.com',
            snapshot(
                [
                    'gnosyrewolf: User does not have a valid email forwarding address.\n',
                    '\tName, title, postal address and phone for: gnosyrewolf',
                    '\tgnosyrewolf',
                    '\tNo title or description registered',
                    '\tNo postaladdress registered',
                    '\tNo phone number registered',
                ]
            ),
        ],
        [
            'invalidmfa@ldap.example.com',
            snapshot(
                [
                    'invalidmfa: User does not have a valid email forwarding address.\n',
                    '\tName, title, postal address and phone for: invalidmfa',
                    '\tbad mfa',
                    '\tNo title or description registered',
                    '\tNo postaladdress registered',
                    '\tNo phone number registered',
                ]
            ),
        ],
        [
            'invalidmfasingle@ldap.example.com',
            snapshot(
                [
                    'invalidmfasingle: User does not have a valid email forwarding address.\n',
                    '\tName, title, postal address and phone for: invalidmfasingle',
                    '\tbad mfa',
                    '\tNo title or description registered',
                    '\tNo postaladdress registered',
                    '\tNo phone number registered',
                ]
            ),
        ],
    ],
)
def test_expand_ldap_nomfa(run_simexpander, req_ldapserver, target, bounce):
    assert run_simexpander(target) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': bounce,
                }
            ],
            'unparsed': [Is(f'Original Recipient: {target}'), Is(f'Non-terminal: {target}')],
        }
    )


def test_expand_ldap_nomfa_onvacation(run_simexpander, req_ldapserver):
    assert run_simexpander('invalidmfavac@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'vacation.mail.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['invalidmfavac@vacation.mail.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: invalidmfavac@ldap.example.com',
                'Non-terminal: invalidmfavac@ldap.example.com',
                'Terminal: invalidmfavac@vacation.mail.example.com',
            ],
        }
    )


def test_expand_ldap_ambiguous(run_simexpander, req_ldapserver):
    assert run_simexpander('eunice.jones@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': ['eunice jones: Ambiguous user', 'eunice', 'eunicej\tSVP', 'eunicex\tSVP'],
                }
            ],
            'unparsed': ['Original Recipient: eunice.jones@ldap.example.com', 'Non-terminal: eunice.jones@ldap.example.com'],
        }
    )


@pytest.mark.parametrize(
    'target',
    [
        'shadow@ldap.example.com',
        'shadowed.alias@ldap.example.com',
    ],
)
def test_expand_ldap_precedence(run_simexpander, req_ldapserver, target):
    assert run_simexpander(target) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['shadowuser@forwarded.example.com'],
                }
            ],
            'unparsed': [Is(f'Original Recipient: {target}'), Is(f'Non-terminal: {target}'), 'Terminal: shadowuser@forwarded.example.com'],
        }
    )


def test_expand_ldap_weird_rule(run_simexpander, req_ldapserver):
    assert run_simexpander('shadowish@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'shadowish.%.ldap.example.com-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['simexpand@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: shadowish@ldap.example.com',
                'Non-terminal: shadowish@ldap.example.com',
                'Non-terminal: uid=simexpand,ou=people,dc=example,dc=com',
                'Terminal: simexpand@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_danglingref(run_simexpander, req_ldapserver):
    assert run_simexpander('dangle@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['dangle-errors@ldap.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': ['address not found: uid=notarealuser,ou=people,dc=example,dc=com'],
                }
            ],
            'unparsed': [
                'Original Recipient: dangle@ldap.example.com',
                'Non-terminal: dangle@ldap.example.com',
                'Non-terminal: uid=notarealuser,ou=people,dc=example,dc=com',
            ],
        }
    )


def test_expand_ldap_group_associated_domain(run_simexpander, req_ldapserver):
    assert run_simexpander('testgroup@otherldap.domain.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'testgroup-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: testgroup@otherldap.domain.example.com',
                'Non-terminal: testgroup@otherldap.domain.example.com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_complex(run_simexpander, req_ldapserver):
    assert run_simexpander('complex.group@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['complex.group-errors@ldap.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'uid=eunicej,ou=people,dc=example,dc=com : Group member exists but does not have a valid email forwarding address.\n',
                        'Group permission conditions not met: cn=membersonly fail,ou=groups,dc=example,dc=com',
                        'If you have any questions, please contact the group owner: membersonly.fail-owner@ldap.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'complex.group-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['eunicex@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'complex.group-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser1@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.org',
                    'sender': 'complex.group-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser2@example.org'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'complex.group-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser3@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'moderated.group-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'moderated.group@ldap.example.com',
                    'recipients': ['simexpand@ldap.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: complex.group@ldap.example.com',
                'Non-terminal: complex.group@ldap.example.com',
                'Terminal: testuser3@example.edu',
                'Terminal: testuser2@example.org',
                'Terminal: testuser1@example.edu',
                'Moderated: cn=moderated group,ou=groups,dc=example,dc=com',
                'Suppressed: uid=testuser,ou=people,dc=example,dc=com',
                'Suppressed: testuser@forwarded.example.com',
                'Non-terminal: uid=eunicex,ou=people,dc=example,dc=com',
                'Terminal: eunicex@forwarded.example.com',
                'Non-terminal: uid=eunicej,ou=people,dc=example,dc=com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd_ps(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pm.pd.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.pm.pd.ps@example.com', 'perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd.ps@ldap-new.example.com',
                'Moderated: perm.mod.pm.pd.ps@ldap-new.example.com',
                'Suppressed: uid=perm-mod-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-pd-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd_ps_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.pd.ps.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-pd-psmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.ps.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-pd-ps-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd.ps.pgp@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pd.ps.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm mod pm pd ps,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-mod-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-ps-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-ps-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd_ps_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.pd.ps.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pm.pd.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.pm.pd.ps@example.com', 'perm.moderator@example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.ps.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-pd-ps-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd.ps.pgnp@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pd.ps.pgnp@ldap-new.example.com',
                'Moderated: cn=perm mod pm pd ps,ou=groups,dc=example,dc=com',
                'Suppressed: uid=perm-mod-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-pd-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-pd-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-ps-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-ps-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd_ps_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-mod-pm-pd-psmember0@ldap-new.example.com', 'perm.mod.pm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pm-pd-psmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pm-pd-psmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pm-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd_ps_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.mod.pm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-mod-pm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-mod-pm-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd_ps_sender(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm.mod.pm.pd.ps@example.com', 'perm.mod.pm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.mod.pm.pd.ps@example.com',
                    'recipients': ['perm-mod-pm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.mod.pm.pd.ps@example.com',
                    'recipients': ['perm-mod-pm-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd_ps(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.pm.pd.ps@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.pm.pd.ps-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd.ps@ldap-new.example.com',
                'Suppressed: uid=perm-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-pd-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd_ps_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.pd.ps.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-pd-psmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.ps.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-pd-ps-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd.ps.pgp@ldap-new.example.com',
                'Non-terminal: perm.pm.pd.ps.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm pm pd ps,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pd-ps-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-ps-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd_ps_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.pd.ps.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm.pm.pd.ps.pgnp-errors@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: cn=perm pm pd ps,ou=groups,dc=example,dc=com',
                        'If you have any questions, please contact the group owner: perm.pm.pd.ps-owner@ldap-new.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.ps.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-pd-ps-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd.ps.pgnp@ldap-new.example.com',
                'Non-terminal: perm.pm.pd.ps.pgnp@ldap-new.example.com',
                'Suppressed: uid=perm-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-pd-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-pd-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pd-ps-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-ps-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd_ps_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-pm-pd-psmember0@ldap-new.example.com', 'perm.pm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pm-pd-psmember0@ldap-new.example.com',
                    'recipients': ['perm-pm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pm-pd-psmember0@ldap-new.example.com',
                    'recipients': ['perm-pm-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd_ps_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.pm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-pm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-pm-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd_ps_sender(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm.pm.pd.ps@example.com', 'perm.pm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.pm.pd.ps@example.com',
                    'recipients': ['perm-pm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.pm.pd.ps@example.com',
                    'recipients': ['perm-pm-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.pm.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-pm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_ps(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pm.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.pm.ps@example.com', 'perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.ps@ldap-new.example.com',
                'Moderated: perm.mod.pm.ps@ldap-new.example.com',
                'Suppressed: uid=perm-mod-pm-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pm-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_ps_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.ps.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-psmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.ps.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-ps-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.ps.pgp@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.ps.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm mod pm ps,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-mod-pm-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-ps-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-ps-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_ps_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.ps.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pm.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.pm.ps@example.com', 'perm.moderator@example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.ps.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-ps-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.ps.pgnp@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.ps.pgnp@ldap-new.example.com',
                'Moderated: cn=perm mod pm ps,ou=groups,dc=example,dc=com',
                'Suppressed: uid=perm-mod-pm-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pm-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-ps-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-ps-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_ps_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-mod-pm-psmember0@ldap-new.example.com', 'perm.mod.pm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pm-psmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pm-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pm-psmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pm-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.ps@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pm-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_ps_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.mod.pm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'header_from': 'perm.mod.pm.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.pm.ps@example.com', 'perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.ps@ldap-new.example.com',
                'Moderated: perm.mod.pm.ps@ldap-new.example.com',
                'Suppressed: uid=perm-mod-pm-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pm-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_ps_sender(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm.mod.pm.ps@example.com', 'perm.mod.pm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.mod.pm.ps@example.com',
                    'recipients': ['perm-mod-pm-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.mod.pm.ps@example.com',
                    'recipients': ['perm-mod-pm-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.ps@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pm-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_ps(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.pm.ps@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.pm.ps-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.pm.ps@ldap-new.example.com',
                'Suppressed: uid=perm-pm-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-pm-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_ps_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.ps.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-psmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.ps.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-ps-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.ps.pgp@ldap-new.example.com',
                'Non-terminal: perm.pm.ps.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm pm ps,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-pm-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pm-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pm-ps-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-ps-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_ps_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.ps.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm.pm.ps.pgnp-errors@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: cn=perm pm ps,ou=groups,dc=example,dc=com',
                        'If you have any questions, please contact the group owner: perm.pm.ps-owner@ldap-new.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.ps.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-ps-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.ps.pgnp@ldap-new.example.com',
                'Non-terminal: perm.pm.ps.pgnp@ldap-new.example.com',
                'Suppressed: uid=perm-pm-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-pm-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pm-ps-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-ps-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_ps_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-pm-psmember0@ldap-new.example.com', 'perm.pm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pm-psmember0@ldap-new.example.com',
                    'recipients': ['perm-pm-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pm-psmember0@ldap-new.example.com',
                    'recipients': ['perm-pm-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.ps@ldap-new.example.com',
                'Non-terminal: perm.pm.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-pm-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pm-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_ps_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.pm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['randomuser@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.pm.ps@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.pm.ps-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.pm.ps@ldap-new.example.com',
                'Suppressed: uid=perm-pm-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-pm-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_ps_sender(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm.pm.ps@example.com', 'perm.pm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.pm.ps@example.com',
                    'recipients': ['perm-pm-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.pm.ps@example.com',
                    'recipients': ['perm-pm-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.ps@ldap-new.example.com',
                'Non-terminal: perm.pm.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-pm-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pm-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pm.pd@ldap-new.example.com',
                    'recipients': ['perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd@ldap-new.example.com',
                'Moderated: perm.mod.pm.pd@ldap-new.example.com',
                'Suppressed: uid=perm-mod-pm-pdmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-pdmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pm-pdmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.pd.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-pdmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-pd-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd.pgp@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pd.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm mod pm pd,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-mod-pm-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pdmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.pd.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pm.pd@ldap-new.example.com',
                    'recipients': ['perm.moderator@example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-pd-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd.pgnp@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pd.pgnp@ldap-new.example.com',
                'Moderated: cn=perm mod pm pd,ou=groups,dc=example,dc=com',
                'Suppressed: uid=perm-mod-pm-pdmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-pdmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pm-pdmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pm-pdmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pd-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pd-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-mod-pm-pdmember0@ldap-new.example.com', 'perm.mod.pm.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pm-pdmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pm-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pm-pdmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pm-pdmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pd@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pm-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pd_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.mod.pm.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-mod-pm-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-mod-pm-pdmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pd@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pd@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pm-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.pm.pd@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.pm.pd-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd@ldap-new.example.com',
                'Suppressed: uid=perm-pm-pdmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-pdmember1@forwarded.example.com',
                'Suppressed: uid=perm-pm-pdmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.pd.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-pdmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-pd-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd.pgp@ldap-new.example.com',
                'Non-terminal: perm.pm.pd.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm pm pd,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-pm-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pdmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pd-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.pd.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm.pm.pd.pgnp-errors@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: cn=perm pm pd,ou=groups,dc=example,dc=com',
                        'If you have any questions, please contact the group owner: perm.pm.pd-owner@ldap-new.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-pd-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd.pgnp@ldap-new.example.com',
                'Non-terminal: perm.pm.pd.pgnp@ldap-new.example.com',
                'Suppressed: uid=perm-pm-pdmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-pdmember1@forwarded.example.com',
                'Suppressed: uid=perm-pm-pdmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pm-pdmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pd-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pd-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-pm-pdmember0@ldap-new.example.com', 'perm.pm.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pm-pdmember0@ldap-new.example.com',
                    'recipients': ['perm-pm-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pm-pdmember0@ldap-new.example.com',
                    'recipients': ['perm-pm-pdmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd@ldap-new.example.com',
                'Non-terminal: perm.pm.pd@ldap-new.example.com',
                'Non-terminal: uid=perm-pm-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pd_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.pm.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-pm-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-pm-pdmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pd@ldap-new.example.com',
                'Non-terminal: perm.pm.pd@ldap-new.example.com',
                'Non-terminal: uid=perm-pm-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pm@ldap-new.example.com',
                    'recipients': ['perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm@ldap-new.example.com',
                'Moderated: perm.mod.pm@ldap-new.example.com',
                'Suppressed: uid=perm-mod-pmmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pmmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pmmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pmmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pmmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pmmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pgp@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm mod pm,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-mod-pmmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pmmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pmmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pmmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pm.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pm@ldap-new.example.com',
                    'recipients': ['perm.moderator@example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pm-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm.pgnp@ldap-new.example.com',
                'Non-terminal: perm.mod.pm.pgnp@ldap-new.example.com',
                'Moderated: cn=perm mod pm,ou=groups,dc=example,dc=com',
                'Suppressed: uid=perm-mod-pmmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pmmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pmmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pmmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pm-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pm-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-mod-pmmember0@ldap-new.example.com', 'perm.mod.pm@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pmmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pmmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pmmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pmmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm@ldap-new.example.com',
                'Non-terminal: perm.mod.pm@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pmmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pmmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pmmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pmmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pm_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.mod.pm@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'header_from': 'perm.mod.pm@ldap-new.example.com',
                    'recipients': ['perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pm@ldap-new.example.com',
                'Moderated: perm.mod.pm@ldap-new.example.com',
                'Suppressed: uid=perm-mod-pmmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pmmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pmmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pmmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.pm@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.pm-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.pm@ldap-new.example.com',
                'Suppressed: uid=perm-pmmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pmmember1@forwarded.example.com',
                'Suppressed: uid=perm-pmmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pmmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pmmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pmmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pgp@ldap-new.example.com',
                'Non-terminal: perm.pm.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm pm,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-pmmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pmmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pmmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pmmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pm.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm.pm.pgnp-errors@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: cn=perm pm,ou=groups,dc=example,dc=com',
                        'If you have any questions, please contact the group owner: perm.pm-owner@ldap-new.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pm-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm.pgnp@ldap-new.example.com',
                'Non-terminal: perm.pm.pgnp@ldap-new.example.com',
                'Suppressed: uid=perm-pmmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pmmember1@forwarded.example.com',
                'Suppressed: uid=perm-pmmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pmmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pm-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pm-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-pmmember0@ldap-new.example.com', 'perm.pm@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pmmember0@ldap-new.example.com',
                    'recipients': ['perm-pmmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pm-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pmmember0@ldap-new.example.com',
                    'recipients': ['perm-pmmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pm@ldap-new.example.com',
                'Non-terminal: perm.pm@ldap-new.example.com',
                'Non-terminal: uid=perm-pmmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pmmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pmmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pmmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pm_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.pm@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['randomuser@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.pm@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.pm-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.pm@ldap-new.example.com',
                'Suppressed: uid=perm-pmmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pmmember1@forwarded.example.com',
                'Suppressed: uid=perm-pmmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pmmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd_ps(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pd.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.pd.ps@example.com', 'perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd.ps@ldap-new.example.com',
                'Moderated: perm.mod.pd.ps@ldap-new.example.com',
                'Suppressed: uid=perm-mod-pd-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pd-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pd-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd_ps_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pd.ps.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pd-psmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.ps.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pd-ps-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd.ps.pgp@ldap-new.example.com',
                'Non-terminal: perm.mod.pd.ps.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm mod pd ps,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-mod-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pd-ps-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-ps-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd_ps_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pd.ps.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pd.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.pd.ps@example.com', 'perm.moderator@example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.ps.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pd-ps-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd.ps.pgnp@ldap-new.example.com',
                'Non-terminal: perm.mod.pd.ps.pgnp@ldap-new.example.com',
                'Moderated: cn=perm mod pd ps,ou=groups,dc=example,dc=com',
                'Suppressed: uid=perm-mod-pd-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pd-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pd-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pd-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pd-ps-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-ps-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd_ps_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-mod-pd-psmember0@ldap-new.example.com', 'perm.mod.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pd-psmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pd-psmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.mod.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd_ps_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.mod.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-mod-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-mod-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.mod.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd_ps_sender(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm.mod.pd.ps@example.com', 'perm.mod.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.mod.pd.ps@example.com',
                    'recipients': ['perm-mod-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.mod.pd.ps@example.com',
                    'recipients': ['perm-mod-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.mod.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd_ps(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.pd.ps@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.pd.ps-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.pd.ps@ldap-new.example.com',
                'Suppressed: uid=perm-pd-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pd-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-pd-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd_ps_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pd.ps.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pd-psmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.ps.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pd-ps-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pd.ps.pgp@ldap-new.example.com',
                'Non-terminal: perm.pd.ps.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm pd ps,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pd-ps-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-ps-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd_ps_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pd.ps.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm.pd.ps.pgnp-errors@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: cn=perm pd ps,ou=groups,dc=example,dc=com',
                        'If you have any questions, please contact the group owner: perm.pd.ps-owner@ldap-new.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.ps.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pd-ps-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pd.ps.pgnp@ldap-new.example.com',
                'Non-terminal: perm.pd.ps.pgnp@ldap-new.example.com',
                'Suppressed: uid=perm-pd-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pd-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-pd-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pd-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pd-ps-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-ps-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd_ps_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-pd-psmember0@ldap-new.example.com', 'perm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pd-psmember0@ldap-new.example.com',
                    'recipients': ['perm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pd-psmember0@ldap-new.example.com',
                    'recipients': ['perm-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd_ps_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd_ps_sender(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm.pd.ps@example.com', 'perm.pd.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.pd.ps@example.com',
                    'recipients': ['perm-pd-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.pd.ps@example.com',
                    'recipients': ['perm-pd-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pd.ps@ldap-new.example.com',
                'Non-terminal: perm.pd.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-pd-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pd-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_ps(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.ps@example.com', 'perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.ps@ldap-new.example.com',
                'Moderated: perm.mod.ps@ldap-new.example.com',
                'Suppressed: uid=perm-mod-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_ps_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.ps.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-psmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.ps.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-ps-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.ps.pgp@ldap-new.example.com',
                'Non-terminal: perm.mod.ps.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm mod ps,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-mod-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-ps-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-ps-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_ps_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.ps.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.ps@example.com', 'perm.moderator@example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.ps.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-ps-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.ps.pgnp@ldap-new.example.com',
                'Non-terminal: perm.mod.ps.pgnp@ldap-new.example.com',
                'Moderated: cn=perm mod ps,ou=groups,dc=example,dc=com',
                'Suppressed: uid=perm-mod-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-ps-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-ps-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_ps_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-mod-psmember0@ldap-new.example.com', 'perm.mod.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-psmember0@ldap-new.example.com',
                    'header_from': 'perm.mod.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.ps@example.com', 'perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.ps@ldap-new.example.com',
                'Moderated: perm.mod.ps@ldap-new.example.com',
                'Suppressed: uid=perm-mod-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_ps_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.mod.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'header_from': 'perm.mod.ps@ldap-new.example.com',
                    'recipients': ['perm.mod.ps@example.com', 'perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.ps@ldap-new.example.com',
                'Moderated: perm.mod.ps@ldap-new.example.com',
                'Suppressed: uid=perm-mod-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_ps_sender(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm.mod.ps@example.com', 'perm.mod.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.mod.ps@example.com',
                    'recipients': ['perm-mod-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.mod.ps@example.com',
                    'recipients': ['perm-mod-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.ps@ldap-new.example.com',
                'Non-terminal: perm.mod.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_ps(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.ps@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.ps-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.ps@ldap-new.example.com',
                'Suppressed: uid=perm-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_ps_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.ps.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-psmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.ps.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-ps-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.ps.pgp@ldap-new.example.com',
                'Non-terminal: perm.ps.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm ps,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-ps-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-ps-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_ps_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.ps.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm.ps.pgnp-errors@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: cn=perm ps,ou=groups,dc=example,dc=com',
                        'If you have any questions, please contact the group owner: perm.ps-owner@ldap-new.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.ps.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-ps-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.ps.pgnp@ldap-new.example.com',
                'Non-terminal: perm.ps.pgnp@ldap-new.example.com',
                'Suppressed: uid=perm-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-psmember0@forwarded.example.com',
                'Non-terminal: uid=perm-ps-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-ps-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_ps_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-psmember0@ldap-new.example.com', 'perm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-psmember0@ldap-new.example.com',
                    'recipients': ['perm-psmember0@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.ps@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.ps-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.ps@ldap-new.example.com',
                'Suppressed: uid=perm-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_ps_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['randomuser@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.ps@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.ps-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.ps@ldap-new.example.com',
                'Suppressed: uid=perm-psmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-psmember1@forwarded.example.com',
                'Suppressed: uid=perm-psmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_ps_sender(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm.ps@example.com', 'perm.ps@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.ps@example.com',
                    'recipients': ['perm-psmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.ps-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm.ps@example.com',
                    'recipients': ['perm-psmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.ps@ldap-new.example.com',
                'Non-terminal: perm.ps@ldap-new.example.com',
                'Non-terminal: uid=perm-psmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-psmember1@forwarded.example.com',
                'Non-terminal: uid=perm-psmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-psmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pd@ldap-new.example.com',
                    'recipients': ['perm.moderator@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd@ldap-new.example.com',
                'Moderated: perm.mod.pd@ldap-new.example.com',
                'Suppressed: uid=perm-mod-pdmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pdmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pdmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pd.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pdmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pd-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd.pgp@ldap-new.example.com',
                'Non-terminal: perm.mod.pd.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm mod pd,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-mod-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pdmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pd-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod.pd.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.pd@ldap-new.example.com',
                    'recipients': ['perm.moderator@example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-mod-pd-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd.pgnp@ldap-new.example.com',
                'Non-terminal: perm.mod.pd.pgnp@ldap-new.example.com',
                'Moderated: cn=perm mod pd,ou=groups,dc=example,dc=com',
                'Suppressed: uid=perm-mod-pdmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pdmember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-pdmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-pdmember0@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pd-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pd-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-mod-pdmember0@ldap-new.example.com', 'perm.mod.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pdmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-pdmember0@ldap-new.example.com',
                    'recipients': ['perm-mod-pdmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd@ldap-new.example.com',
                'Non-terminal: perm.mod.pd@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_pd_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.mod.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-mod-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-mod-pdmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.pd@ldap-new.example.com',
                'Non-terminal: perm.mod.pd@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.pd@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.pd-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.pd@ldap-new.example.com',
                'Suppressed: uid=perm-pdmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pdmember1@forwarded.example.com',
                'Suppressed: uid=perm-pdmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd_pgp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pd.pgp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pdmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.pgp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pd-pgpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pd.pgp@ldap-new.example.com',
                'Non-terminal: perm.pd.pgp@ldap-new.example.com',
                'Non-terminal: cn=perm pd,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pdmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pd-pgpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-pgpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd_pgnp(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.pd.pgnp@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm.pd.pgnp-errors@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: cn=perm pd,ou=groups,dc=example,dc=com',
                        'If you have any questions, please contact the group owner: perm.pd-owner@ldap-new.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd.pgnp-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-pd-pgnpmember@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pd.pgnp@ldap-new.example.com',
                'Non-terminal: perm.pd.pgnp@ldap-new.example.com',
                'Suppressed: uid=perm-pdmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-pdmember1@forwarded.example.com',
                'Suppressed: uid=perm-pdmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-pdmember0@forwarded.example.com',
                'Non-terminal: uid=perm-pd-pgnpmember,ou=people,dc=example,dc=com',
                'Terminal: perm-pd-pgnpmember@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-pdmember0@ldap-new.example.com', 'perm.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pdmember0@ldap-new.example.com',
                    'recipients': ['perm-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-pdmember0@ldap-new.example.com',
                    'recipients': ['perm-pdmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pd@ldap-new.example.com',
                'Non-terminal: perm.pd@ldap-new.example.com',
                'Non-terminal: uid=perm-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_pd_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.pd@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-pdmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.pd-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-pdmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.pd@ldap-new.example.com',
                'Non-terminal: perm.pd@ldap-new.example.com',
                'Non-terminal: uid=perm-pdmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-pdmember1@forwarded.example.com',
                'Non-terminal: uid=perm-pdmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-pdmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'sender@expansion.test', 'perm.mod@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-modmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm-modmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod@ldap-new.example.com',
                'Non-terminal: perm.mod@ldap-new.example.com',
                'Non-terminal: uid=perm-modmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-modmember1@forwarded.example.com',
                'Non-terminal: uid=perm-modmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-modmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_member(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-modmember0@ldap-new.example.com', 'perm.mod@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-modmember0@ldap-new.example.com',
                    'recipients': ['perm-modmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-modmember0@ldap-new.example.com',
                    'recipients': ['perm-modmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod@ldap-new.example.com',
                'Non-terminal: perm.mod@ldap-new.example.com',
                'Non-terminal: uid=perm-modmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-modmember1@forwarded.example.com',
                'Non-terminal: uid=perm-modmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-modmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_domain(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'randomuser@ldap-new.example.com', 'perm.mod@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-modmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'randomuser@ldap-new.example.com',
                    'recipients': ['perm-modmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod@ldap-new.example.com',
                'Non-terminal: perm.mod@ldap-new.example.com',
                'Non-terminal: uid=perm-modmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-modmember1@forwarded.example.com',
                'Non-terminal: uid=perm-modmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-modmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_dupe_member(run_simexpander, req_ldapserver):
    # The important bit: the member that is in both groups should still receive
    # the message.
    assert run_simexpander(['-F', 'perm-dupe-member-pgmember0@ldap-new.example.com', 'perm.dupe.member.pg@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-dupe-member-pgmember0@ldap-new.example.com',
                    'recipients': ['perm.dupe.member.pg-errors@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: cn=perm dupe member,ou=groups,dc=example,dc=com',
                        'If you have any questions, please contact the group owner: perm.dupe.member-owner@ldap-new.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.dupe.member.pg-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-dupe-member-pgmember0@ldap-new.example.com',
                    'recipients': ['perm-dupe-member-pgmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.dupe.member.pg-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-dupe-member-pgmember0@ldap-new.example.com',
                    'recipients': ['perm-dupe-member-pgmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.dupe.member.pg-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-dupe-member-pgmember0@ldap-new.example.com',
                    'recipients': ['perm-dupe-membermember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.dupe.member.pg@ldap-new.example.com',
                'Non-terminal: perm.dupe.member.pg@ldap-new.example.com',
                'Suppressed: uid=perm-dupe-membermember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-dupe-membermember0@forwarded.example.com',
                'Non-terminal: uid=perm-dupe-membermember1,ou=people,dc=example,dc=com',
                'Terminal: perm-dupe-membermember1@forwarded.example.com',
                'Non-terminal: uid=perm-dupe-member-pgmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-dupe-member-pgmember1@forwarded.example.com',
                'Non-terminal: uid=perm-dupe-member-pgmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-dupe-member-pgmember0@forwarded.example.com',
            ],
        }
    )


@pytest.mark.parametrize(
    'sender',
    [
        'perm-dupe-membermember0@ldap-new.example.com',
        'perm-dupe-membermember1@ldap-new.example.com',
    ],
)
def test_expand_ldap_group_perm_dupe_member_permitted(run_simexpander, req_ldapserver, sender):
    # Make sure the member that is in both groups is still permitted to send
    # to the child group.
    assert run_simexpander(['-F', sender, 'perm.dupe.member.pg@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.dupe.member-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': ['perm-dupe-membermember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.dupe.member.pg-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': ['perm-dupe-member-pgmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.dupe.member.pg-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': ['perm-dupe-member-pgmember1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.dupe.member.pg-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': Is(sender),
                    'recipients': ['perm-dupe-membermember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.dupe.member.pg@ldap-new.example.com',
                'Non-terminal: perm.dupe.member.pg@ldap-new.example.com',
                'Non-terminal: cn=perm dupe member,ou=groups,dc=example,dc=com',
                'Non-terminal: uid=perm-dupe-membermember0,ou=people,dc=example,dc=com',
                'Terminal: perm-dupe-membermember0@forwarded.example.com',
                'Non-terminal: uid=perm-dupe-membermember1,ou=people,dc=example,dc=com',
                'Terminal: perm-dupe-membermember1@forwarded.example.com',
                'Non-terminal: uid=perm-dupe-member-pgmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-dupe-member-pgmember1@forwarded.example.com',
                'Non-terminal: uid=perm-dupe-member-pgmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-dupe-member-pgmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_full_expansion(run_simexpander, req_ldapserver):
    # Make sure that a suppressed member of a child group still counts as a
    # member of the parent group for permissions.
    assert run_simexpander(['-F', 'perm-full-expansionmember0@ldap-new.example.com', 'perm.full.expansion.pg@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-full-expansionmember0@ldap-new.example.com',
                    'recipients': ['perm.full.expansion.pg-errors@ldap-new.example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: cn=perm full expansion,ou=groups,dc=example,dc=com',
                        'If you have any questions, please contact the group owner: perm.full.expansion-owner@ldap-new.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.full.expansion.pg-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-full-expansionmember0@ldap-new.example.com',
                    'recipients': ['perm-full-expansion-pgmember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.full.expansion.pg-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-full-expansionmember0@ldap-new.example.com',
                    'recipients': ['perm-full-expansion-pgmember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.full.expansion.pg@ldap-new.example.com',
                'Non-terminal: perm.full.expansion.pg@ldap-new.example.com',
                'Suppressed: uid=perm-full-expansionmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-full-expansionmember1@forwarded.example.com',
                'Suppressed: uid=perm-full-expansionmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-full-expansionmember0@forwarded.example.com',
                'Non-terminal: uid=perm-full-expansion-pgmember1,ou=people,dc=example,dc=com',
                'Terminal: perm-full-expansion-pgmember1@forwarded.example.com',
                'Non-terminal: uid=perm-full-expansion-pgmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-full-expansion-pgmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_full_expansion_childps(run_simexpander, req_ldapserver):
    # Make sure that permissions on a child group still result in full
    # suppression when the parent group's permissions are not met.
    assert run_simexpander(['-F', 'perm-full-expansionowner@example.com', 'perm.full.expansion.pg@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-full-expansionowner@example.com',
                    'recipients': ['perm-full-expansionowner@example.com'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.full.expansion.pg@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.full.expansion.pg-owner@ldap-new.example.com',
                    ],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.full.expansion.pg@ldap-new.example.com',
                'Suppressed: cn=perm full expansion,ou=groups,dc=example,dc=com',
                'Suppressed: uid=perm-full-expansionmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-full-expansionmember1@forwarded.example.com',
                'Suppressed: uid=perm-full-expansionmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-full-expansionmember0@forwarded.example.com',
                'Suppressed: uid=perm-full-expansion-pgmember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-full-expansion-pgmember1@forwarded.example.com',
                'Suppressed: uid=perm-full-expansion-pgmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-full-expansion-pgmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_autoreply(run_simexpander, req_ldapserver):
    assert run_simexpander('perm.autoreply@ldap-new.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': [
                        'Group permission conditions not met: perm.autoreply@ldap-new.example.com',
                        'If you have any questions, please contact the group owner: perm.autoreply-owner@ldap-new.example.com',
                    ],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'vacation.mail.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm.autoreply@vacation.mail.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.autoreply@ldap-new.example.com',
                'Suppressed: uid=perm-autoreplymember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-autoreplymember1@forwarded.example.com',
                'Suppressed: uid=perm-autoreplymember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-autoreplymember0@forwarded.example.com',
                'Terminal: perm.autoreply@vacation.mail.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_autoreply_permitted(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-autoreplyowner@example.com', 'perm.autoreply@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'vacation.mail.example.com',
                    'sender': 'perm-autoreplyowner@example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-autoreplyowner@example.com',
                    'recipients': ['perm.autoreply@vacation.mail.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.autoreply-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-autoreplyowner@example.com',
                    'recipients': ['perm-autoreplymember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.autoreply-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-autoreplyowner@example.com',
                    'recipients': ['perm-autoreplymember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.autoreply@ldap-new.example.com',
                'Non-terminal: perm.autoreply@ldap-new.example.com',
                'Non-terminal: uid=perm-autoreplymember1,ou=people,dc=example,dc=com',
                'Terminal: perm-autoreplymember1@forwarded.example.com',
                'Non-terminal: uid=perm-autoreplymember0,ou=people,dc=example,dc=com',
                'Terminal: perm-autoreplymember0@forwarded.example.com',
                'Terminal: perm.autoreply@vacation.mail.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_autoreply(run_simexpander, req_ldapserver):
    assert run_simexpander('perm.mod.autoreply@ldap-new.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.mod.autoreply-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.mod.autoreply@ldap-new.example.com',
                    'recipients': ['perm-mod-autoreplyowner@example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'vacation.mail.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['perm.mod.autoreply@vacation.mail.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.autoreply@ldap-new.example.com',
                'Moderated: perm.mod.autoreply@ldap-new.example.com',
                'Suppressed: uid=perm-mod-autoreplymember1,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-autoreplymember1@forwarded.example.com',
                'Suppressed: uid=perm-mod-autoreplymember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-mod-autoreplymember0@forwarded.example.com',
                'Terminal: perm.mod.autoreply@vacation.mail.example.com',
            ],
        }
    )


def test_expand_ldap_group_perm_mod_autoreply_permitted(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-mod-autoreplyowner@example.com', 'perm.mod.autoreply@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'vacation.mail.example.com',
                    'sender': 'perm-mod-autoreplyowner@example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-autoreplyowner@example.com',
                    'recipients': ['perm.mod.autoreply@vacation.mail.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.autoreply-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-autoreplyowner@example.com',
                    'recipients': ['perm-mod-autoreplymember0@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.mod.autoreply-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-mod-autoreplyowner@example.com',
                    'recipients': ['perm-mod-autoreplymember1@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: perm.mod.autoreply@ldap-new.example.com',
                'Non-terminal: perm.mod.autoreply@ldap-new.example.com',
                'Non-terminal: uid=perm-mod-autoreplymember1,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-autoreplymember1@forwarded.example.com',
                'Non-terminal: uid=perm-mod-autoreplymember0,ou=people,dc=example,dc=com',
                'Terminal: perm-mod-autoreplymember0@forwarded.example.com',
                'Terminal: perm.mod.autoreply@vacation.mail.example.com',
            ],
        }
    )


def test_expand_ldap_group_mod_format(run_simexpander, req_ldapserver):
    assert run_simexpander('perm.format@ldap-new.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': 'perm.format-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'header_from': 'perm.format@ldap-new.example.com',
                    'recipients': ['perm-formatnonowner@example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.format@ldap-new.example.com',
                'Moderated: perm.format@ldap-new.example.com',
                'Suppressed: uid=perm-formatmember0,ou=people,dc=example,dc=com',
                'Suppressed: perm-formatmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_permitted_format(run_simexpander, req_ldapserver):
    assert run_simexpander(['-F', 'perm-formatnonowner@example.com', 'perm.format@ldap-new.example.com']) == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'perm.format-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'perm-formatnonowner@example.com',
                    'recipients': ['perm-formatmember0@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: perm.format@ldap-new.example.com',
                'Non-terminal: perm.format@ldap-new.example.com',
                'Non-terminal: uid=perm-formatmember0,ou=people,dc=example,dc=com',
                'Terminal: perm-formatmember0@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_external_format(run_simexpander, req_ldapserver):
    assert run_simexpander('external.format@ldap.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.format-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['"quoted testuser1"@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.format-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['"quoted testuser2"@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.format-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser1@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.format-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser2@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.format-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser3@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.format-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser4@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.format-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser5@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.format-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser6@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.format-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser7@example.edu'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.format-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser8@example.edu'],
                },
            ],
            'unparsed': [
                'Original Recipient: external.format@ldap.example.com',
                'Non-terminal: external.format@ldap.example.com',
                'Terminal: testuser8@example.edu',
                'Terminal: testuser7@example.edu',
                'Terminal: "quoted testuser2"@example.edu',
                'Terminal: "quoted testuser1"@example.edu',
                'Terminal: testuser6@example.edu',
                'Terminal: testuser5@example.edu',
                'Terminal: testuser4@example.edu',
                'Terminal: testuser3@example.edu',
                'Terminal: testuser2@example.edu',
                'Terminal: testuser1@example.edu',
            ],
        }
    )


def test_expand_ldap_group_external_utf8(run_simexpander, req_ldapserver):
    assert run_simexpander('external.utf8@ldap-new.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'example.edu',
                    'sender': 'external.utf8-errors@ldap-new.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser1@example.edu'],
                }
            ],
            'unparsed': [
                'Original Recipient: external.utf8@ldap-new.example.com',
                'Non-terminal: external.utf8@ldap-new.example.com',
                'Terminal: testuser1@example.edu',
            ],
        }
    )


def test_expand_ldap_user_badforward(run_simexpander, req_ldapserver):
    assert run_simexpander('badforwardingaddr@ldap-new.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['badforwardingaddr1@forwarded.example.com'],
                },
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'sender@expansion.test',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['badforwardingaddr2@forwarded.example.com'],
                },
            ],
            'unparsed': [
                'Original Recipient: badforwardingaddr@ldap-new.example.com',
                'Non-terminal: badforwardingaddr@ldap-new.example.com',
                'Terminal: badforwardingaddr2@forwarded.example.com',
                'Terminal: badforwardingaddr1@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_subsearch(run_simexpander, req_ldapserver):
    assert run_simexpander('member@control.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'hostname': 'forwarded.example.com',
                    'sender': 'control.member-errors@ldap.example.com',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['testuser@forwarded.example.com'],
                }
            ],
            'unparsed': [
                'Original Recipient: member@control.example.com',
                'Non-terminal: member@control.example.com',
                'Non-terminal: uid=testuser,ou=people,dc=example,dc=com',
                'Terminal: testuser@forwarded.example.com',
            ],
        }
    )


def test_expand_ldap_group_subsearch_miss(run_simexpander, req_ldapserver):
    assert run_simexpander('nonmember@control.example.com') == snapshot(
        {
            'parsed': [
                {
                    'envelope_id': IsEnvelopeId,
                    'body_inode': 0,
                    'expansion_level': 1,
                    'sender': '',
                    '8bitmime': False,
                    'jailed': False,
                    'bounceable': True,
                    'puntable': True,
                    'original_sender': 'sender@expansion.test',
                    'recipients': ['sender@expansion.test'],
                    'header_from': IsMailerDaemon,
                    'bounce_lines': ['address not found: nonmember@control.example.com'],
                }
            ],
            'unparsed': ['Original Recipient: nonmember@control.example.com', 'Non-terminal: nonmember@control.example.com'],
        }
    )
