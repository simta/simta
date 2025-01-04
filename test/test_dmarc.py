import json
import os
import subprocess

import pytest


EQUIV_DOMAINS = [
    'example.com',
    'EXAMPLE.COM',
    'sub.example.com',
    'example.example.com',
]


@pytest.fixture
def run_simdmarc(simta_config, tool_path, dnsserver):
    def _run_simdmarc(domains):
        psl = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'public_suffix_list.dat')
        dns_config = {
            'core': {
                'dns': {
                    'host': '127.0.0.1',
                    'port': dnsserver['port'],
                    'timeout': 2,
                }
            },
            'receive': {
                'dmarc': {
                    'public_suffix_file': psl,
                },
            },
        }

        args = [
            tool_path('simdmarc'),
            '-f', simta_config,
            '-U', json.dumps(dns_config),
        ]

        if isinstance(domains, list):
            args.extend(domains)
        else:
            args.append(domains)

        res = subprocess.run(
            [x for x in args if x is not None],
            check=True,
            capture_output=True,
            text=True,
        )

        return res.stdout.splitlines()
    return _run_simdmarc


@pytest.mark.parametrize('dkim', [
    None,
    'example.edu',
    'example.com',
])
@pytest.mark.parametrize('spf', EQUIV_DOMAINS)
@pytest.mark.parametrize('hfrom', EQUIV_DOMAINS)
def test_dmarc_pass(run_simdmarc, hfrom, spf, dkim):
    dmarc = run_simdmarc([hfrom, spf, dkim])
    assert dmarc[0] == 'DMARC lookup result: policy reject, percent 100, result reject'
    assert dmarc[1].startswith('DMARC policy result')
    assert dmarc[1].endswith(': pass')


@pytest.mark.parametrize('dkim', [
    None,
    'example.edu',
])
@pytest.mark.parametrize('spf', [
    None,
    'example.edu',
    'notexample.com',
    'nexample.com',
    'xample.com',
    'e.xample.com',
    'example.com.example.edu',
])
@pytest.mark.parametrize('hfrom', EQUIV_DOMAINS)
def test_dmarc_fail(run_simdmarc, hfrom, spf, dkim):
    dmarc = run_simdmarc([hfrom, spf, dkim])
    assert dmarc[0] == 'DMARC lookup result: policy reject, percent 100, result reject'
    assert dmarc[1].startswith('DMARC policy result')
    assert dmarc[1].endswith(': reject')


@pytest.mark.parametrize('dkim', [
    ['example.com', 'example.edu'],
    ['example.edu', 'example.com'],
    ['example.com', 'example.edu', 'example.com'],
    ['example.edu', 'example.com', 'example.edu'],
])
def test_dmarc_multiple_dkim(run_simdmarc, dkim):
    dmarc = run_simdmarc(['example.com', 'example.edu'] + dkim)
    assert dmarc[1].startswith('DMARC policy result')
    assert dmarc[1].endswith(': pass')


# FIXME: test sp, subdomains with conflicting policies, etc.
