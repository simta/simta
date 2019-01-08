import json
import os
import subprocess

import pytest


@pytest.fixture
def expansion_config(simta_config, real_tmpdir):
    passwd_file = os.path.join(real_tmpdir, 'passwd')
    alias_file = os.path.join(real_tmpdir, 'alias')
    alias_db = os.path.join(real_tmpdir, 'alias.db')
    with open(passwd_file, 'w') as f:
        f.write('testuser:x:1000:1000::{}:/sbin/nologin\n'.format(real_tmpdir))
    with open(alias_file, 'w') as f:
        f.write('testuser: anotheruser\n')
        f.write('external: testuser@example.edu\n')
        f.write('password: testuser@password.example.com\n')
        f.write('chained: testuser@alias.example.com\n')
        f.write('group: testuser@alias.example.com, groupuser@example.com\n')
        f.write('group2-errors: anotheruser\n')
        f.write('group2: group@alias.example.com\n')

    simta_config['config']['domain'] = {
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

    return simta_config


@pytest.fixture
def run_simexpander(expansion_config, tool_path):
    def _run_simexpander(addresses):
        subprocess.check_output([
            tool_path('simalias'),
            '-f', expansion_config['config_file'],
            '-U', json.dumps(expansion_config['config']),
        ])

        return subprocess.check_output([
            tool_path('simexpander'),
            '-f', expansion_config['config_file'],
            '-U', json.dumps(expansion_config['config']),
            addresses,
        ])
    return _run_simexpander


def parse_expander_output(output):
    envelopes = []
    cur_obj = None
    for line in output.split('\n'):
        if cur_obj == None:
            if line == '{':
                cur_obj = line
        else:
            cur_obj += line
            if line == '}':
                envelopes.append(json.loads(cur_obj))
                cur_obj = None
    return envelopes


def test_expand_none(run_simexpander):
    res = parse_expander_output(run_simexpander('testuser@none.example.com'))
    assert len(res) == 1
    assert res[0]['recipients'] == [ 'testuser@none.example.com' ]


def test_expand_password(run_simexpander):
    res = parse_expander_output(run_simexpander('testuser@password.example.com'))
    assert len(res) == 1
    assert res[0]['recipients'] == [ 'testuser@password.example.com' ]


def test_expand_password_nonexist(run_simexpander):
    res = parse_expander_output(run_simexpander('baduser@password.example.com'))
    assert len(res) == 1
    assert res[0]['recipients'] == [ 'sender@expansion.test' ]
    assert res[0]['sender'] == ''

def test_expand_alias(run_simexpander):
    res = parse_expander_output(run_simexpander('testuser@alias.example.com'))
    assert len(res) == 1
    assert res[0]['recipients'] == [ 'anotheruser@masquerade.example.com' ]

def test_expand_alias_external(run_simexpander):
    res = parse_expander_output(run_simexpander('external@alias.example.com'))
    assert len(res) == 1
    assert res[0]['recipients'] == [ 'testuser@example.edu' ]

def test_expand_alias_password(run_simexpander):
    res = parse_expander_output(run_simexpander('password@alias.example.com'))
    assert len(res) == 1
    assert res[0]['recipients'] == [ 'testuser@password.example.com' ]

def test_expand_alias_chained(run_simexpander):
    res = parse_expander_output(run_simexpander('chained@alias.example.com'))
    assert len(res) == 1
    assert res[0]['recipients'] == [ 'anotheruser@masquerade.example.com' ]

def test_expand_alias_group(run_simexpander):
    res = parse_expander_output(run_simexpander('group@alias.example.com'))
    assert len(res) == 2
    assert res[0]['recipients'] == [ 'anotheruser@masquerade.example.com' ]
    assert res[0]['sender'] == 'sender@expansion.test'
    assert res[1]['recipients'] == [ 'groupuser@example.com' ]
    assert res[1]['sender'] == 'sender@expansion.test'

def test_expand_alias_group_errorsto(run_simexpander):
    res = parse_expander_output(run_simexpander('group2@alias.example.com'))
    assert len(res) == 2
    assert res[0]['recipients'] == [ 'anotheruser@masquerade.example.com' ]
    assert res[0]['sender'] == 'group2-errors@alias.example.com'
    assert res[1]['recipients'] == [ 'groupuser@example.com' ]
    assert res[1]['sender'] == 'group2-errors@alias.example.com'
