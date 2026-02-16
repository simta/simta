#!/usr/bin/env python

import os
import subprocess

import pytest

from dirty_equals import IsStr
from inline_snapshot import snapshot


@pytest.fixture
def acl_file():
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files', 'testacl')


@pytest.fixture
def run_simrbl(tool_path):
    def _run_simrbl(args):
        args = [tool_path('simrbl'), *args]
        return subprocess.run(args, check=False, capture_output=True, text=True)

    return _run_simrbl


@pytest.mark.parametrize(
    'entry,result',
    [
        ('foo', snapshot(['foo', 'found', 'in', IsStr, 'foo', '(bar)'])),
        ('foO', snapshot(['foO', 'found', 'in', IsStr, 'foo', '(bar)'])),
        ('FOO', snapshot(['FOO', 'found', 'in', IsStr, 'foo', '(bar)'])),
        ('baz', snapshot(['baz', 'found', 'in', IsStr, 'BAZ', '(local', 'policy)'])),
        ('quux', snapshot(['quux', 'found', 'in', IsStr, 'Quux', '(local', 'policy)'])),
    ],
)
def test_acl_file(run_simrbl, acl_file, entry, result):
    res = run_simrbl(['-f', acl_file, '-t', entry])
    assert res.returncode == 1
    assert res.stdout.split() == result


@pytest.mark.parametrize(
    'entry',
    [
        'fooba',
        'bar',
        'foof',
        'doot',
    ],
)
def test_acl_file_miss(run_simrbl, acl_file, entry):
    res = run_simrbl(['-f', acl_file, '-t', entry])
    assert res.returncode == 0
    assert res.stdout == 'not found\n'


@pytest.mark.parametrize(
    'ip,result',
    [
        ('127.0.0.2', snapshot(['127.0.0.2', 'found', 'in', IsStr, '127.0.0.2', '(local', 'policy)'])),
        ('127.0.0.3', snapshot(['127.0.0.3', 'found', 'in', IsStr, '127.0.0.3', '(bar)'])),
        ('127.0.0.4', snapshot(['127.0.0.4', 'found', 'in', IsStr, 'foo', '(bar)'])),
        ('127.0.1.1', snapshot(['127.0.1.1', 'found', 'in', IsStr, '127.0.1.0', '(baz)'])),
        ('127.0.1.254', snapshot(['127.0.1.254', 'found', 'in', IsStr, '127.0.1.0', '(baz)'])),
        ('127.0.2.1', snapshot(['127.0.2.1', 'found', 'in', IsStr, '127.0.2.1', '(local', 'policy)'])),
    ],
)
def test_acl_file_ip(run_simrbl, acl_file, ip, result):
    res = run_simrbl(['-f', acl_file, ip])
    assert res.returncode == 1
    assert res.stdout.split() == result


@pytest.mark.parametrize(
    'entry',
    [
        '127.0.0.1',
        '127.0.2.2',
        '127.0.3.1',
    ],
)
def test_acl_file_ip_miss(run_simrbl, acl_file, entry):
    res = run_simrbl(['-f', acl_file, entry])
    assert res.returncode == 0
    assert res.stdout == 'not found\n'
