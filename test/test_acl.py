#!/usr/bin/env python

import os
import subprocess

import pytest


@pytest.fixture
def acl_file():
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files', 'testacl')


@pytest.fixture
def run_simrbl(tool_path):
    def _run_simrbl(args):
        args = [tool_path('simrbl')] + args
        return subprocess.run(args, check=False, capture_output=True, text=True)

    return _run_simrbl


@pytest.mark.parametrize('entry', [
    ('foo', 'bar'),
    ('foO', 'bar'),
    ('FOO', 'bar'),
    ('baz', 'local policy'),
    ('quux', 'local policy'),
])
def test_acl_file(run_simrbl, acl_file, entry):
    res = run_simrbl(['-f', acl_file, '-t', entry[0]])
    assert res.returncode == 1
    assert res.stdout.startswith(f'{entry[0]} found in ')
    assert res.stdout.endswith(f' ({entry[1]})\n')


@pytest.mark.parametrize('entry', [
    'fooba',
    'bar',
    'foof',
    'doot',
])
def test_acl_file_miss(run_simrbl, acl_file, entry):
    res = run_simrbl(['-f', acl_file, '-t', entry])
    assert res.returncode == 0
    assert res.stdout == 'not found\n'


def test_acl_file_ip(run_simrbl, acl_file):
    res = run_simrbl(['-f', acl_file, '127.0.0.2'])
    assert res.returncode == 1
    assert res.stdout.startswith('127.0.0.2 found in ')
    assert res.stdout.endswith(' 127.0.0.2 (local policy)\n')

    res = run_simrbl(['-f', acl_file, '127.0.0.3'])
    assert res.returncode == 1
    assert res.stdout.startswith('127.0.0.3 found in ')
    assert res.stdout.endswith(' 127.0.0.3 (bar)\n')

    res = run_simrbl(['-f', acl_file, '127.0.0.4'])
    assert res.returncode == 1
    assert res.stdout.startswith('127.0.0.4 found in ')
    assert res.stdout.endswith(' foo (bar)\n')


def test_acl_file_ip_miss(run_simrbl, acl_file):
    res = run_simrbl(['-f', acl_file, '127.0.0.1'])
    assert res.returncode == 0
    assert res.stdout == 'not found\n'
