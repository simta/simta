import json
import subprocess

import pytest


@pytest.fixture
def run_simdmarc(simta_config, tool_path, dnsserver, req_dnsserver):
    def _run_simdmarc(domains):
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
            tool_path('simdmarc'),
            '-f', simta_config,
            '-U', json.dumps(dns_config),
        ]

        if isinstance(domains, list):
            args.extend(domains)
        else:
            args.append(domains)

        res = subprocess.run(
            args,
            check=True,
            capture_output=True,
            text=True,
        )

        return res.stdout.splitlines()
    return _run_simdmarc


def test_dmarc_pass(run_simdmarc):
    dmarc = run_simdmarc(['example.com', 'example.com'])
    assert dmarc[0] == 'DMARC lookup result: policy reject, percent 100, result reject'
    assert dmarc[1] == 'DMARC policy result for example.com/example.com: pass'


def test_dmarc_fail(run_simdmarc):
    dmarc = run_simdmarc('example.com')
    assert dmarc[0] == 'DMARC lookup result: policy reject, percent 100, result reject'
    assert dmarc[1] == 'DMARC policy result for example.com: reject'

# FIXME: test more complex scenarios, orgdomain
