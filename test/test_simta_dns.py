#!/usr/bin/env python3

import json
import subprocess

import pytest


def parse_connect_output(output):
    parsed = []
    for line in output.splitlines():
        if 'Trying address record' not in line:
            continue
        parsed.append(line.split(': ')[-1])

    return {
        'parsed': parsed,
        'output': output,
    }


@pytest.fixture
def run_simconnect(tool_path, simta_config, dnsserver, req_dnsserver):
    def _run_simconnect(hostname):
        dns_config = {
            'core': {
                'dns': {
                    'host': '127.0.0.1',
                    'port': dnsserver['port'],
                    'timeout': 2,
                }
            }
        }
        args = [
            tool_path('simconnect'),
            '-f', simta_config,
            '-U', json.dumps(dns_config),
            '-l', hostname
        ]

        return parse_connect_output(subprocess.run(args, check=True, capture_output=True, text=True).stderr)
    return _run_simconnect


def test_connect_a(run_simconnect):
    res = run_simconnect('ipv4.example.com')
    assert res['parsed'] == ['172.24.0.1']


def test_connect_aaaa(run_simconnect):
    res = run_simconnect('ipv6.example.com')
    assert res['parsed'] == ['100::1']


@pytest.mark.parametrize('domain', [
    'mixed.example.com',
    'addr-redirect.example.com',
    'addr-chain.example.com',
])
def test_connect_address(domain, run_simconnect):
    res = run_simconnect(domain)
    assert res['parsed'] == ['100::2', '172.24.0.2']


@pytest.mark.parametrize('domain', [
    'real.example.com',
    'mx-redirect.example.com',
    'mx-chain.example.com',
])
def test_connect_mx(domain, run_simconnect):
    res = run_simconnect(domain)
    assert res['parsed'] == ['172.24.0.1', '100::1', '100::2', '172.24.0.2']


@pytest.mark.parametrize('domain', [
    'nonexist.example.com',
    'dangling.example.com',
    'bad-mx.example.com',
    'bad-mx-cname.example.com',
])
def test_connect_noserver(domain, run_simconnect):
    res = run_simconnect(domain)
    assert len(res['parsed']) == 0


@pytest.mark.parametrize('domain', [
    'nonexist.example.com',
    'dangling.example.com',
    'bad-mx.example.com',
    'bad-mx-cname.example.com',
])
def test_connect_bounce(domain, run_simconnect):
    res = run_simconnect(domain)
    assert len(res['parsed']) == 0
    assert 'address record missing, bouncing mail' in res['output']


@pytest.mark.parametrize('domain', [
    'ipv4.example.com',
    'ipv6.example.com',
    'mixed.example.com',
    'addr-redirect.example.com',
    'addr-chain.example.com',
    'real.example.com',
    'mx-redirect.example.com',
    'mx-chain.example.com',
    'mixed-mx.example.com',
    'timeout',
])
def test_connect_nobounce(domain, run_simconnect):
    res = run_simconnect(domain)
    assert 'address record missing, bouncing mail' not in res['output']


def test_connect_nobounce_timeout(tool_path, simta_config):
    dns_config = {
        'core': {
            'dns': {
                'host': '127.0.0.1',
                'port': 666,
                'timeout': 1,
            }
        }
    }
    args = [
        tool_path('simconnect'),
        '-f', simta_config,
        '-U', json.dumps(dns_config),
        '-l', 'nonexist.example.com',
    ]

    res = parse_connect_output(subprocess.run(args, check=True, capture_output=True, text=True).stderr)
    assert len(res['parsed']) == 0
    assert 'address record missing, bouncing mail' not in res['output']
