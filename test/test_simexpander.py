#!/usr/bin/env python3

import json
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


def parse_expander_output(output):
    parsed = []
    unparsed = []
    cur_obj = None
    for line in output.splitlines():
        if cur_obj is None:
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
        subprocess.run(
            [
                tool_path('simalias'),
                '-f', expansion_config,
            ],
            check=True,
        )

        args = [
            tool_path('simexpander'),
            '-f', expansion_config,
        ]
        if isinstance(addresses, list):
            args.extend(addresses)
        else:
            args.append(addresses)

        return parse_expander_output(subprocess.run(args, check=True, capture_output=True, text=True).stdout)
    return _run_simexpander


def test_expand_none(run_simexpander):
    res = run_simexpander('testuser@none.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@none.example.com']


def test_expand_quotes(run_simexpander):
    res = run_simexpander([
        '-F', '"."@example.com',
        '"testuser with spaces"@none.example.com',
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['"testuser with spaces"@none.example.com']
    assert res['parsed'][0]['sender'] == '"."@example.com'


def test_expand_password(run_simexpander):
    res = run_simexpander('testuser@password.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@password.example.com']


def assert_nonexist(res):
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert res['parsed'][0]['sender'] == ''
    assert 'address not found: ' in ''.join(res['parsed'][0]['bounce_lines'])


def test_expand_password_nonexist(run_simexpander):
    assert_nonexist(run_simexpander('baduser@password.example.com'))


def test_expand_password_forward(run_simexpander):
    res = run_simexpander('forwarduser@password.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == ['user@example.com']
    assert res['parsed'][1]['recipients'] == ['user@example.edu']


def test_expand_alias(run_simexpander):
    res = run_simexpander('testuser@alias.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['anotheruser@masquerade.example.com']


def test_expand_alias_nonexist(run_simexpander):
    assert_nonexist(run_simexpander('baduser@alias.example.com'))


@pytest.mark.parametrize('slug', SUBADDR_TESTS)
def test_expand_alias_subaddress(run_simexpander, slug):
    res = run_simexpander('testuser{}@alias.example.com'.format(slug))
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['anotheruser@masquerade.example.com']


def test_expand_alias_subaddress_nonexist(run_simexpander):
    assert_nonexist(run_simexpander('testuser_foo@alias.example.com'))


def test_expand_alias_external(run_simexpander):
    res = run_simexpander('external@alias.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@example.edu']


def test_expand_alias_password(run_simexpander):
    res = run_simexpander('password@alias.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@password.example.com']


def test_expand_alias_chained(run_simexpander):
    res = run_simexpander('chained@alias.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['anotheruser@masquerade.example.com']


def test_expand_alias_group(run_simexpander):
    res = run_simexpander('group@alias.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == ['groupuser@example.com']
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'
    assert res['parsed'][1]['recipients'] == ['anotheruser@masquerade.example.com']
    assert res['parsed'][1]['sender'] == 'sender@expansion.test'


def test_expand_alias_group_errorsto(run_simexpander):
    res = run_simexpander('group2@alias.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == ['groupuser@example.com']
    assert res['parsed'][0]['sender'] == 'group2-errors@alias.example.com'
    assert res['parsed'][1]['recipients'] == ['anotheruser@masquerade.example.com']
    assert res['parsed'][1]['sender'] == 'group2-errors@alias.example.com'


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
    res = run_simexpander(target)
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['anotheruser@masquerade.example.com']
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'


def test_expand_srs(run_simexpander, run_simsrs):
    addr = 'testsender@example.edu'
    srs = run_simsrs(addr)
    res = run_simexpander(srs)
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testsender@example.edu']


def test_expand_ldap_user_nonexist(run_simexpander, req_ldapserver):
    assert_nonexist(run_simexpander('baduser@ldap.example.com'))


def test_expand_ldap_user(run_simexpander, req_ldapserver):
    res = run_simexpander('testuser@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'


@pytest.mark.parametrize('slug', SUBADDR_TESTS)
def test_expand_ldap_subaddress(run_simexpander, req_ldapserver, slug):
    res = run_simexpander('testuser{}@ldap.example.com'.format(slug))
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'


def test_expand_ldap_subaddress_nonexist(run_simexpander, req_ldapserver):
    assert_nonexist(run_simexpander('testuser_foo@alias.example.com'))


@pytest.mark.parametrize(
    'target',
    [
        'testgroup@ldap.example.com',
        'testgroup.alias@ldap.example.com',
        'testgroup_alias@ldap.example.com',
        'testgroup.*.!#$%&-/=?^_`{|}~\'+@ldap.example.com',
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
    res = run_simexpander(target)
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
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
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'


@pytest.mark.parametrize('slug', [
    'errors',
    'requests',
])
def test_expand_ldap_group_FOOto(run_simexpander, req_ldapserver, slug):
    res = run_simexpander('testgroup.nonowner-{}@ldap.example.com'.format(slug))
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == ['{}to@forwarded.example.com'.format(slug)]
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'
    assert res['parsed'][1]['recipients'] == ['{}to@example.edu'.format(slug)]
    assert res['parsed'][1]['sender'] == 'sender@expansion.test'


def test_expand_ldap_group_weird_spacing(run_simexpander, req_ldapserver):
    res = run_simexpander('_testgroup__weird___spacing____issue_@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == '_testgroup._weird._.spacing._._issue_-errors@ldap.example.com'


def test_expand_ldap_group_empty(run_simexpander, req_ldapserver):
    res = run_simexpander('testgroup.empty@ldap.example.com')
    assert len(res['parsed']) == 0


@pytest.mark.parametrize('sender', [
    'simexpand@ldap.example.com',
    'SIMEXPAND@LDAP.EXAMPLE.COM',
    'SIMEXPAND@EXAMPLE.COM',
    'SIMEXPAND@P.EXAMPLE.COM'
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
    assert res['parsed'][0]['recipients'] == ['simexpand@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'membersonly.succeed-errors@ldap.example.com'


@pytest.mark.parametrize('sender', [
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
])
def test_expand_ldap_group_membersonly_nonmember(run_simexpander, req_ldapserver, sender):
    res = run_simexpander([
        '-F', sender,
        'membersonly.succeed@ldap.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [sender]
    assert res['parsed'][0]['sender'] == ''
    assert 'Group permission conditions not met: ' in ''.join(res['parsed'][0]['bounce_lines'])


def test_expand_ldap_group_membersonly_no(run_simexpander, req_ldapserver):
    res = run_simexpander('membersonly.fail@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert res['parsed'][0]['sender'] == ''
    assert 'Group permission conditions not met: ' in ''.join(res['parsed'][0]['bounce_lines'])


def test_expand_ldap_group_membersonly_permitted(run_simexpander, req_ldapserver):
    res = run_simexpander('public.supergroup@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']


def test_expand_ldap_group_membersonly_recursive(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'simexpand@ldap.example.com',
        'membersonly.recurse@ldap.example.com',
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['simexpand@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'membersonly.recurse.subgroup-errors@ldap.example.com'


# FIXME: if a subgroup is private, no membersonly bounce should be created
# if membership is public, the bounce should go to the owners of the containing
# group.

def test_expand_ldap_group_nested(run_simexpander, req_ldapserver):
    res = run_simexpander('nested.group.1@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'nested.group.3-errors@ldap.example.com'


def test_expand_ldap_group_recursive(run_simexpander, req_ldapserver):
    res = run_simexpander('loop.group.1@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'loop.group.1-errors@ldap.example.com'


@pytest.mark.parametrize('sender', [
    'simexpand@example.com',
    'simexpand@ldap.example.com',
    'simexpand@dap.example.com',
    'simexpand@notldap.example.com',
    'simexpand@nomatch.example.com',
    'simexpand@subdomain.ldap.example.com',
    'simexpand@subdomain.dap.example.com',
    'simexpand@subdomain.notldap.example.com',
    'simexpand@subdomain.nomatch.example.com',
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
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'moderated.group-errors@ldap.example.com'


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
    ]
)
def test_expand_ldap_group_moderated_nonmod(run_simexpander, req_ldapserver, sender, target):
    res = run_simexpander([
        '-F', sender,
        '{}@ldap.example.com'.format(target),
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['simexpand@ldap.example.com']
    assert res['parsed'][0]['sender'] == '{}-errors@ldap.example.com'.format(target)


@pytest.mark.parametrize(
    'sender',
    [
        'simexpand@ldap.example.com',               # moderator
        'simexpand@subdomain.ldap.example.com',     # mod permitted subdomain match
        'simexpand@example.com',                    # mod permitted subdomain match
        'simexpand@notldap.example.com',            # mod permitted subdomain match
        'simexpand@nomatch.example.com',            # mod permitted subdomain match
        'simexpand@subdomain.notldap.example.com',  # mod permitted subdomain match
        'testuser@ldap.example.com',                # member email
        'testuser@forwarded.example.com',           # member forwarding address
        'testuser@subdomain.ldap.example.com',      # member permitted subdomain match
    ],
)
def test_expand_ldap_group_moderated_membersonly(run_simexpander, req_ldapserver, sender):
    res = run_simexpander([
        '-F', sender,
        'mo.moderated.group@ldap.example.com',
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'mo.moderated.group-errors@ldap.example.com'
    assert 'bounce_lines' not in res['parsed'][0]


def test_expand_ldap_group_moderated_badmoderator(run_simexpander, req_ldapserver):
    res = run_simexpander(['bad.moderated.group@ldap.example.com'])
    assert len(res['parsed']) == 2
    # Group error
    assert res['parsed'][0]['recipients'] == ['bad.moderated.group-errors@ldap.example.com']
    assert res['parsed'][0]['sender'] == ''
    assert 'bad permitted senders: ' in ''.join(res['parsed'][0]['bounce_lines'])
    assert 'bad moderators: ' in ''.join(res['parsed'][0]['bounce_lines'])
    # Bounce to sender
    assert res['parsed'][1]['recipients'] == ['sender@expansion.test']
    assert res['parsed'][1]['sender'] == ''
    assert 'Group permission conditions not met: ' ''.join(res['parsed'][1]['bounce_lines'])


@pytest.mark.parametrize(
    'sender',
    [
        'testuser@ldap.example.com',    # subgroup member
        'sender@expansion.test',        # random non-member
        'simexpand@ldap.example.com',   # subgroup moderator
    ],
)
def test_expand_ldap_group_moderated_membersonly_permitted(run_simexpander, req_ldapserver, sender):
    res = run_simexpander([
        '-F', sender,
        'mo.moderated.public.supergroup@ldap.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'mo.moderated.subgroup-errors@ldap.example.com'


@pytest.mark.parametrize(
    'sender',
    [
        'testuser@ldap.example.com',    # subgroup member
        'simexpand@ldap.example.com',   # subgroup moderator
    ],
)
def test_expand_ldap_group_moderated_membersonly_nonpermitted_succeed(run_simexpander, req_ldapserver, sender):
    res = run_simexpander([
        '-F', sender,
        'mo.moderated.public.nonpermitted@ldap.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'mo.moderated.subgroup-errors@ldap.example.com'


def test_expand_ldap_group_moderated_membersonly_nonpermitted(run_simexpander, req_ldapserver):
    res = run_simexpander('mo.moderated.public.nonpermitted@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['simexpand@ldap.example.com']
    assert res['parsed'][0]['sender'] == 'mo.moderated.subgroup-errors@ldap.example.com'


# FIXME: test_expand_ldap_group_moderated_modloop


@pytest.mark.parametrize(
    'sender',
    [
        'testuser@example.edu',
        'otheruser@sub.example.edu',
    ],
)
def test_expand_ldap_group_permitted_domain(run_simexpander, req_ldapserver, sender):
    res = run_simexpander([
        '-F', sender,
        'permitted.domain@ldap.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'permitted.domain-errors@ldap.example.com'


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
    res = run_simexpander([
        '-F', sender,
        'permitted.domain@ldap.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [sender]
    assert res['parsed'][0]['sender'] == ''
    assert 'Group permission conditions not met: ' in ''.join(res['parsed'][0]['bounce_lines'])


def test_expand_ldap_user_vacation(run_simexpander, req_ldapserver):
    res = run_simexpander('onvacation@ldap.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == ['onvacation@forwarded.example.com']
    assert res['parsed'][1]['recipients'] == ['onvacation@vacation.mail.example.com']


def test_expand_ldap_user_autoreply(run_simexpander, req_ldapserver):
    res = run_simexpander('autoreply@ldap.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == ['autoreply@forwarded.example.com']
    assert res['parsed'][1]['recipients'] == ['autoreply@vacation.mail.example.com']


def test_expand_ldap_user_autoreply_past(run_simexpander, req_ldapserver):
    res = run_simexpander('autoreplypast@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['autoreply@forwarded.example.com']


def test_expand_ldap_user_autoreply_future_end(run_simexpander, req_ldapserver):
    res = run_simexpander('autoreplyend@ldap.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['recipients'] == ['autoreply@forwarded.example.com']
    assert res['parsed'][1]['recipients'] == ['autoreplyend@vacation.mail.example.com']


def test_expand_ldap_user_autoreply_no_start(run_simexpander, req_ldapserver):
    res = run_simexpander('autoreplynostart@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['autoreply@forwarded.example.com']


def test_expand_ldap_user_autoreply_future_start(run_simexpander, req_ldapserver):
    res = run_simexpander('autoreplyfuturestart@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['autoreply@forwarded.example.com']


def test_expand_ldap_user_autoreply_future(run_simexpander, req_ldapserver):
    res = run_simexpander('autoreplyfuture@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['autoreply@forwarded.example.com']


def test_expand_ldap_group_autoreply(run_simexpander, req_ldapserver):
    res = run_simexpander('vacation.group@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['vacation.group@vacation.mail.example.com']
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'


def test_expand_ldap_group_member_nomfa(run_simexpander, req_ldapserver):
    res = run_simexpander('nomfa@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['nomfa-errors@ldap.example.com']
    assert res['parsed'][0]['sender'] == ''
    assert 'Group member exists but does not have a valid email forwarding address.' in ''.join(res['parsed'][0]['bounce_lines'])


def test_expand_ldap_group_member_invalidmfa(run_simexpander, req_ldapserver):
    res = run_simexpander('invalidmfa.group@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['invalidmfa.group-errors@ldap.example.com']
    assert res['parsed'][0]['sender'] == ''
    assert 'Group member exists but does not have a valid email forwarding address.' in ''.join(res['parsed'][0]['bounce_lines'])


@pytest.mark.parametrize(
    'target',
    [
        'nomfa.suppress@ldap.example.com',
        'invalidmfa.suppress@ldap.example.com',
    ]
)
def test_expand_ldap_group_member_nomfa_suppress(run_simexpander, req_ldapserver, target):
    res = run_simexpander(target)
    assert res['parsed'] == []


@pytest.mark.parametrize(
    'target',
    [
        'flowerysong@ldap.example.com',
        'gnosyrewolf@ldap.example.com',
        'invalidmfa@ldap.example.com',
        'invalidmfasingle@ldap.example.com',
    ],
)
def test_expand_ldap_nomfa(run_simexpander, req_ldapserver, target):
    res = run_simexpander(target)
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert res['parsed'][0]['sender'] == ''
    assert 'User does not have a valid email forwarding address.' in ''.join(res['parsed'][0]['bounce_lines'])


def test_expand_ldap_nomfa_onvacation(run_simexpander, req_ldapserver):
    res = run_simexpander('invalidmfavac@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['invalidmfavac@vacation.mail.example.com']


def test_expand_ldap_ambiguous(run_simexpander, req_ldapserver):
    res = run_simexpander('eunice.jones@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert res['parsed'][0]['sender'] == ''
    assert 'Ambiguous user' in ''.join(res['parsed'][0]['bounce_lines'])


@pytest.mark.parametrize(
    'target',
    [
        'shadow@ldap.example.com',
        'shadowed.alias@ldap.example.com',
    ],
)
def test_expand_ldap_precedence(run_simexpander, req_ldapserver, target):
    res = run_simexpander(target)
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['shadowuser@forwarded.example.com']


def test_expand_ldap_weird_rule(run_simexpander, req_ldapserver):
    res = run_simexpander('shadowish@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['simexpand@forwarded.example.com']


def test_expand_ldap_danglingref(run_simexpander, req_ldapserver):
    res = run_simexpander('dangle@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['dangle-errors@ldap.example.com']
    assert res['parsed'][0]['sender'] == ''
    assert 'address not found' in ''.join(res['parsed'][0]['bounce_lines'])


def test_expand_ldap_group_associated_domain(run_simexpander, req_ldapserver):
    res = run_simexpander('testgroup@otherldap.domain.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == ['testuser@forwarded.example.com']
    assert res['parsed'][0]['sender'] == 'testgroup-errors@ldap.example.com'


def test_expand_ldap_group_complex(run_simexpander, req_ldapserver):
    res = run_simexpander('complex.group@ldap.example.com')
    assert len(res['parsed']) == 5
    # moderator copy
    assert res['parsed'][0]['recipients'] == ['simexpand@ldap.example.com']
    assert res['parsed'][0]['sender'] == 'moderated.group-errors@ldap.example.com'
    # valid LDAP members
    assert res['parsed'][1]['hostname'] == 'forwarded.example.com'
    assert res['parsed'][1]['recipients'] == ['eunicex@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'complex.group-errors@ldap.example.com'
    # external member
    assert res['parsed'][2]['hostname'] == 'example.org'
    assert res['parsed'][2]['recipients'] == ['testuser2@example.org']
    assert res['parsed'][2]['sender'] == 'complex.group-errors@ldap.example.com'
    # external members
    assert res['parsed'][3]['hostname'] == 'example.edu'
    assert res['parsed'][3]['recipients'] == ['testuser1@example.edu', 'testuser3@example.edu']
    assert res['parsed'][3]['sender'] == 'complex.group-errors@ldap.example.com'    # bounce for invalid LDAP member
    assert res['parsed'][4]['recipients'] == ['complex.group-errors@ldap.example.com']
    assert res['parsed'][4]['sender'] == ''


def test_expand_ldap_group_perm_mod_pm_pd_ps(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == [
        'perm.mod.pm.pd.ps@example.com',
        'perm.moderator@example.com',
    ]


def test_expand_ldap_group_perm_mod_pm_pd_ps_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.pd.ps.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd.ps.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pm-pd-ps-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == [
        'perm-mod-pm-pd-psmember0@forwarded.example.com',
        'perm-mod-pm-pd-psmember1@forwarded.example.com',
    ]


def test_expand_ldap_group_perm_mod_pm_pd_ps_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.pd.ps.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == [
        'perm.mod.pm.pd.ps@example.com',
        'perm.moderator@example.com',
    ]
    assert res['parsed'][1]['sender'] == 'perm.mod.pm.pd.ps.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pm-pd-ps-pgnpmember@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_pd_ps_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-mod-pm-pd-psmember0@ldap-new.example.com',
        'perm.mod.pm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == [
        'perm-mod-pm-pd-psmember0@forwarded.example.com',
        'perm-mod-pm-pd-psmember1@forwarded.example.com',
    ]


def test_expand_ldap_group_perm_mod_pm_pd_ps_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.mod.pm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == [
        'perm-mod-pm-pd-psmember0@forwarded.example.com',
        'perm-mod-pm-pd-psmember1@forwarded.example.com',
    ]


def test_expand_ldap_group_perm_mod_pm_pd_ps_sender(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm.mod.pm.pd.ps@example.com',
        'perm.mod.pm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == [
        'perm-mod-pm-pd-psmember0@forwarded.example.com',
        'perm-mod-pm-pd-psmember1@forwarded.example.com',
    ]


def test_expand_ldap_group_perm_pm_pd_ps(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_pm_pd_ps_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.pd.ps.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pm.pd.ps.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-pd-ps-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.pm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == [
        'perm-pm-pd-psmember0@forwarded.example.com',
        'perm-pm-pd-psmember1@forwarded.example.com',
    ]


def test_expand_ldap_group_perm_pm_pd_ps_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.pd.ps.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pm.pd.ps.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-pd-ps-pgnpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == ''
    assert res['parsed'][1]['recipients'] == ['perm.pm.pd.ps.pgnp-errors@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][1]['bounce_lines'][0]


def test_expand_ldap_group_perm_pm_pd_ps_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-pm-pd-psmember0@ldap-new.example.com',
        'perm.pm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == [
        'perm-pm-pd-psmember0@forwarded.example.com',
        'perm-pm-pd-psmember1@forwarded.example.com',
    ]


def test_expand_ldap_group_perm_pm_pd_ps_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.pm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == [
        'perm-pm-pd-psmember0@forwarded.example.com',
        'perm-pm-pd-psmember1@forwarded.example.com',
    ]


def test_expand_ldap_group_perm_pm_pd_ps_sender(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm.pm.pd.ps@example.com',
        'perm.pm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == [
        'perm-pm-pd-psmember0@forwarded.example.com',
        'perm-pm-pd-psmember1@forwarded.example.com',
    ]


def test_expand_ldap_group_perm_mod_pm_ps(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == [
        'perm.mod.pm.ps@example.com',
        'perm.moderator@example.com',
    ]


def test_expand_ldap_group_perm_mod_pm_ps_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.ps.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.ps.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pm-ps-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pm.ps-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pm-psmember0@forwarded.example.com', 'perm-mod-pm-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_ps_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.ps.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.mod.pm.ps@example.com', 'perm.moderator@example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pm.ps.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pm-ps-pgnpmember@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_ps_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-mod-pm-psmember0@ldap-new.example.com',
        'perm.mod.pm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pm-psmember0@forwarded.example.com', 'perm-mod-pm-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_ps_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.mod.pm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.mod.pm.ps@example.com', 'perm.moderator@example.com']


def test_expand_ldap_group_perm_mod_pm_ps_sender(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm.mod.pm.ps@example.com',
        'perm.mod.pm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pm-psmember0@forwarded.example.com', 'perm-mod-pm-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pm_ps(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_pm_ps_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.ps.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pm.ps.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-ps-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.pm.ps-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-pm-psmember0@forwarded.example.com', 'perm-pm-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pm_ps_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.ps.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pm.ps.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-ps-pgnpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == ''
    assert res['parsed'][1]['recipients'] == ['perm.pm.ps.pgnp-errors@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][1]['bounce_lines'][0]


def test_expand_ldap_group_perm_pm_ps_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-pm-psmember0@ldap-new.example.com',
        'perm.pm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pm.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-psmember0@forwarded.example.com', 'perm-pm-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pm_ps_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.pm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['randomuser@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_pm_ps_sender(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm.pm.ps@example.com',
        'perm.pm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pm.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-psmember0@forwarded.example.com', 'perm-pm-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_pd(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.moderator@example.com']


def test_expand_ldap_group_perm_mod_pm_pd_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.pd.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pm-pd-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pm.pd-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pm-pdmember0@forwarded.example.com', 'perm-mod-pm-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_pd_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.pd.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.moderator@example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pm.pd.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pm-pd-pgnpmember@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_pd_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-mod-pm-pdmember0@ldap-new.example.com',
        'perm.mod.pm.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pm-pdmember0@forwarded.example.com', 'perm-mod-pm-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_pd_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.mod.pm.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pm-pdmember0@forwarded.example.com', 'perm-mod-pm-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pm_pd(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_pm_pd_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.pd.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pm.pd.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-pd-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.pm.pd-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-pm-pdmember0@forwarded.example.com', 'perm-pm-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pm_pd_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.pd.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pm.pd.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-pd-pgnpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == ''
    assert res['parsed'][1]['recipients'] == ['perm.pm.pd.pgnp-errors@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][1]['bounce_lines'][0]


def test_expand_ldap_group_perm_pm_pd_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-pm-pdmember0@ldap-new.example.com',
        'perm.pm.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pm.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-pdmember0@forwarded.example.com', 'perm-pm-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pm_pd_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.pm.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pm.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-pdmember0@forwarded.example.com', 'perm-pm-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.moderator@example.com']


def test_expand_ldap_group_perm_mod_pm_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pm.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pm-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pm-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pmmember0@forwarded.example.com', 'perm-mod-pmmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pm.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pm-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.moderator@example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pm.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pm-pgnpmember@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-mod-pmmember0@ldap-new.example.com',
        'perm.mod.pm@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pmmember0@forwarded.example.com', 'perm-mod-pmmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pm_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.mod.pm@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pm-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.moderator@example.com']


def test_expand_ldap_group_perm_pm(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_pm_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pm.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.pm-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-pmmember0@forwarded.example.com', 'perm-pmmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pm_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pm.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pm.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pm-pgnpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == ''
    assert res['parsed'][1]['recipients'] == ['perm.pm.pgnp-errors@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][1]['bounce_lines'][0]


def test_expand_ldap_group_perm_pm_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-pmmember0@ldap-new.example.com',
        'perm.pm@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pm-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pmmember0@forwarded.example.com', 'perm-pmmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pm_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.pm@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['randomuser@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_mod_pd_ps(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.mod.pd.ps@example.com', 'perm.moderator@example.com']


def test_expand_ldap_group_perm_mod_pd_ps_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pd.ps.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pd.ps.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pd-ps-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pd-psmember0@forwarded.example.com', 'perm-mod-pd-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pd_ps_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pd.ps.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.mod.pd.ps@example.com', 'perm.moderator@example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pd.ps.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pd-ps-pgnpmember@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pd_ps_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-mod-pd-psmember0@ldap-new.example.com',
        'perm.mod.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pd-psmember0@forwarded.example.com', 'perm-mod-pd-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pd_ps_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.mod.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pd-psmember0@forwarded.example.com', 'perm-mod-pd-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pd_ps_sender(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm.mod.pd.ps@example.com',
        'perm.mod.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pd-psmember0@forwarded.example.com', 'perm-mod-pd-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pd_ps(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_pd_ps_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pd.ps.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pd.ps.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pd-ps-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-pd-psmember0@forwarded.example.com', 'perm-pd-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pd_ps_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pd.ps.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pd.ps.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pd-ps-pgnpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == ''
    assert res['parsed'][1]['recipients'] == ['perm.pd.ps.pgnp-errors@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][1]['bounce_lines'][0]


def test_expand_ldap_group_perm_pd_ps_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-pd-psmember0@ldap-new.example.com',
        'perm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pd-psmember0@forwarded.example.com', 'perm-pd-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pd_ps_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pd-psmember0@forwarded.example.com', 'perm-pd-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pd_ps_sender(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm.pd.ps@example.com',
        'perm.pd.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pd.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pd-psmember0@forwarded.example.com', 'perm-pd-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_ps(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.mod.ps@example.com', 'perm.moderator@example.com']


def test_expand_ldap_group_perm_mod_ps_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.ps.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.ps.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-ps-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.ps-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-psmember0@forwarded.example.com', 'perm-mod-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_ps_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.ps.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.mod.ps@example.com', 'perm.moderator@example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.ps.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-ps-pgnpmember@forwarded.example.com']


def test_expand_ldap_group_perm_mod_ps_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-mod-psmember0@ldap-new.example.com',
        'perm.mod.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.mod.ps@example.com', 'perm.moderator@example.com']


def test_expand_ldap_group_perm_mod_ps_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.mod.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.mod.ps@example.com', 'perm.moderator@example.com']


def test_expand_ldap_group_perm_mod_ps_sender(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm.mod.ps@example.com',
        'perm.mod.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-psmember0@forwarded.example.com', 'perm-mod-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_ps(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_ps_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.ps.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.ps.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-ps-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.ps-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-psmember0@forwarded.example.com', 'perm-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_ps_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.ps.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.ps.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-ps-pgnpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == ''
    assert res['parsed'][1]['recipients'] == ['perm.ps.pgnp-errors@ldap-new.example.com']


def test_expand_ldap_group_perm_ps_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-psmember0@ldap-new.example.com',
        'perm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['perm-psmember0@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_ps_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['randomuser@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_ps_sender(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm.ps@example.com',
        'perm.ps@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.ps-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-psmember0@forwarded.example.com', 'perm-psmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pd(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.moderator@example.com']


def test_expand_ldap_group_perm_mod_pd_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pd.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pd.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pd-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pd-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pdmember0@forwarded.example.com', 'perm-mod-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pd_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod.pd.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm.moderator@example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.pd.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-mod-pd-pgnpmember@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pd_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-mod-pdmember0@ldap-new.example.com',
        'perm.mod.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pdmember0@forwarded.example.com', 'perm-mod-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_pd_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.mod.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-pdmember0@forwarded.example.com', 'perm-mod-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pd(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['sender@expansion.test']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_pd_pgp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pd.pgp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pd.pgp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pd-pgpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == 'perm.pd-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-pdmember0@forwarded.example.com', 'perm-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pd_pgnp(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.pd.pgnp@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.pd.pgnp-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pd-pgnpmember@forwarded.example.com']
    assert res['parsed'][1]['sender'] == ''
    assert res['parsed'][1]['recipients'] == ['perm.pd.pgnp-errors@ldap-new.example.com']


def test_expand_ldap_group_perm_pd_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-pdmember0@ldap-new.example.com',
        'perm.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pdmember0@forwarded.example.com', 'perm-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_pd_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.pd@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.pd-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-pdmember0@forwarded.example.com', 'perm-pdmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'sender@expansion.test',
        'perm.mod@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-modmember0@forwarded.example.com', 'perm-modmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-modmember0@ldap-new.example.com',
        'perm.mod@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-modmember0@forwarded.example.com', 'perm-modmember1@forwarded.example.com']


def test_expand_ldap_group_perm_mod_domain(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'randomuser@ldap-new.example.com',
        'perm.mod@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.mod-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-modmember0@forwarded.example.com', 'perm-modmember1@forwarded.example.com']


def test_expand_ldap_group_perm_dupe_member(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-dupe-member-pgmember0@ldap-new.example.com',
        'perm.dupe.member.pg@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.dupe.member.pg-errors@ldap-new.example.com'
    # The important bit: the member that is in both groups should still receive
    # the message.
    assert res['parsed'][0]['recipients'] == [
        'perm-dupe-member-pgmember0@forwarded.example.com',
        'perm-dupe-member-pgmember1@forwarded.example.com',
        'perm-dupe-membermember1@forwarded.example.com',
    ]
    assert res['parsed'][1]['sender'] == ''
    assert res['parsed'][1]['recipients'] == ['perm.dupe.member.pg-errors@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][1]['bounce_lines'][0]


@pytest.mark.parametrize('sender', [
    'perm-dupe-membermember0@ldap-new.example.com',
    'perm-dupe-membermember1@ldap-new.example.com',
])
def test_expand_ldap_group_perm_dupe_member_permitted(run_simexpander, req_ldapserver, sender):
    # Make sure the member that is in both groups is still permitted to send
    # to the child group.
    res = run_simexpander([
        '-F', sender,
        'perm.dupe.member.pg@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.dupe.member.pg-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == [
        'perm-dupe-member-pgmember0@forwarded.example.com',
        'perm-dupe-member-pgmember1@forwarded.example.com',
        'perm-dupe-membermember1@forwarded.example.com',
    ]
    assert res['parsed'][1]['sender'] == 'perm.dupe.member-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == ['perm-dupe-membermember0@forwarded.example.com']


def test_expand_ldap_group_perm_full_expansion(run_simexpander, req_ldapserver):
    # Make sure that a suppressed member of a child group still counts as a
    # member of the parent group for permissions.
    res = run_simexpander([
        '-F', 'perm-full-expansionmember0@ldap-new.example.com',
        'perm.full.expansion.pg@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.full.expansion.pg-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-full-expansion-pgmember0@forwarded.example.com', 'perm-full-expansion-pgmember1@forwarded.example.com']
    assert res['parsed'][1]['sender'] == ''
    assert res['parsed'][1]['recipients'] == ['perm.full.expansion.pg-errors@ldap-new.example.com']
    assert 'Group permission conditions not met' in res['parsed'][1]['bounce_lines'][0]


def test_expand_ldap_group_perm_full_expansion_childps(run_simexpander, req_ldapserver):
    # Make sure that permissions on a child group still result in full
    # suppression when the parent group's permissions are not met.
    res = run_simexpander([
        '-F', 'perm-full-expansionowner@example.com',
        'perm.full.expansion.pg@ldap-new.example.com'
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == ''
    assert res['parsed'][0]['recipients'] == ['perm-full-expansionowner@example.com']
    assert 'Group permission conditions not met' in res['parsed'][0]['bounce_lines'][0]


def test_expand_ldap_group_perm_autoreply(run_simexpander, req_ldapserver):
    res = run_simexpander('perm.autoreply@ldap-new.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'sender@expansion.test'
    assert res['parsed'][0]['recipients'] == ['perm.autoreply@vacation.mail.example.com']
    assert res['parsed'][1]['sender'] == ''
    assert res['parsed'][1]['recipients'] == ['sender@expansion.test']
    assert 'Group permission conditions not met' in res['parsed'][1]['bounce_lines'][0]


def test_expand_ldap_group_perm_autoreply_permitted(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-autoreplyowner@example.com',
        'perm.autoreply@ldap-new.example.com',
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm-autoreplyowner@example.com'
    assert res['parsed'][0]['recipients'] == ['perm.autoreply@vacation.mail.example.com']
    assert res['parsed'][1]['sender'] == 'perm.autoreply-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == [
        'perm-autoreplymember0@forwarded.example.com',
        'perm-autoreplymember1@forwarded.example.com',
    ]


def test_expand_ldap_group_perm_mod_autoreply(run_simexpander, req_ldapserver):
    res = run_simexpander('perm.mod.autoreply@ldap-new.example.com')
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm.mod.autoreply-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-mod-autoreplyowner@example.com']
    assert res['parsed'][1]['sender'] == 'sender@expansion.test'
    assert res['parsed'][1]['recipients'] == ['perm.mod.autoreply@vacation.mail.example.com']


def test_expand_ldap_group_perm_mod_autoreply_permitted(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-mod-autoreplyowner@example.com',
        'perm.mod.autoreply@ldap-new.example.com',
    ])
    assert len(res['parsed']) == 2
    assert res['parsed'][0]['sender'] == 'perm-mod-autoreplyowner@example.com'
    assert res['parsed'][0]['recipients'] == ['perm.mod.autoreply@vacation.mail.example.com']
    assert res['parsed'][1]['sender'] == 'perm.mod.autoreply-errors@ldap-new.example.com'
    assert res['parsed'][1]['recipients'] == [
        'perm-mod-autoreplymember0@forwarded.example.com',
        'perm-mod-autoreplymember1@forwarded.example.com',
    ]


def test_expand_ldap_group_mod_format(run_simexpander, req_ldapserver):
    res = run_simexpander('perm.format@ldap-new.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.format-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-formatnonowner@example.com']


def test_expand_ldap_group_permitted_format(run_simexpander, req_ldapserver):
    res = run_simexpander([
        '-F', 'perm-formatnonowner@example.com',
        'perm.format@ldap-new.example.com',
    ])
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['sender'] == 'perm.format-errors@ldap-new.example.com'
    assert res['parsed'][0]['recipients'] == ['perm-formatmember0@forwarded.example.com']


def test_expand_ldap_group_external_format(run_simexpander, req_ldapserver):
    res = run_simexpander('external.format@ldap.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [
        'testuser1@example.edu',
        'testuser2@example.edu',
        'testuser3@example.edu',
        'testuser4@example.edu',
        'testuser5@example.edu',
        'testuser6@example.edu',
        '"quoted testuser1"@example.edu',
        '"quoted testuser2"@example.edu',
        'testuser7@example.edu',
        'testuser8@example.edu',
    ]


def test_expand_ldap_group_external_utf8(run_simexpander, req_ldapserver):
    res = run_simexpander('external.utf8@ldap-new.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [
        'testuser1@example.edu',
    ]


def test_expand_ldap_user_badforward(run_simexpander, req_ldapserver):
    res = run_simexpander('badforwardingaddr@ldap-new.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [
        'badforwardingaddr1@forwarded.example.com',
        'badforwardingaddr2@forwarded.example.com',
    ]


def test_expand_ldap_group_subsearch(run_simexpander, req_ldapserver):
    res = run_simexpander('member@control.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [
        'testuser@forwarded.example.com',
    ]
    assert res['parsed'][0]['sender'] == 'control.member-errors@ldap.example.com'


def test_expand_ldap_group_subsearch_miss(run_simexpander, req_ldapserver):
    res = run_simexpander('nonmember@control.example.com')
    assert len(res['parsed']) == 1
    assert res['parsed'][0]['recipients'] == [
        'sender@expansion.test',
    ]
    assert res['parsed'][0]['sender'] == ''
    assert 'address not found: ' in ''.join(res['parsed'][0]['bounce_lines'])
