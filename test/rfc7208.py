#!/usr/bin/env python3

import json
import os
import socket
import subprocess
import time
import warnings

import pytest

from pathlib import Path

try:
    from ruamel.yaml import YAML
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

DISABLED_TESTS = [
    # simta doesn't do IPv4-mapped IPv6 addresses
    'a-cidr6-0-ip4mapped',
    'a-colon-domain-ip4mapped',
    'mx-cidr6-0-ip4mapped',
    'mx-colon-domain-ip4mapped',
    'ip4-mapped-ip6',
    'cidr6-ip4',
    # FIXME: possibly actually broken
    'a-colon-domain',
    'mx-colon-domain',
    'macro-mania-in-domain',
    # TIMEOUT is not implemented in the test harness
    'timeout',
    'include-temperror',
    'exists-dnserr',
    # denser returns a null-terminated string, so we can't distinguish between
    # a null from the record and the end of the string.
    'a-null',
    'mx-null',
    # we do not implement the p macro, because it sucks
    'p-macro-ip4-novalid',
    'p-macro-ip4-valid',
    'p-macro-ip6-novalid',
    'p-macro-ip6-valid',
    'p-macro-multiple',
    # not required by the RFC
    'cidr4-032',
]


def openport(port):
    # Find a usable port by iterating until there's an unconnectable port
    while True:
        try:
            socket.create_connection(('localhost', port), 0.1)
            port += 1
            if port > 65535:
                raise ValueError("exhausted TCP port range without finding a free one")
        except socket.error:
            return port


def pytest_collect_file(parent, file_path):
    if file_path.name.startswith('rfc7208') and file_path.name.endswith('.yml'):
        return SPFFile.from_parent(parent, path=file_path)


class SPFFile(pytest.File):
    def collect(self):
        if not HAS_YAML:
            return

        idx = 0
        for scenario in YAML().load_all(self.path):
            for (k, v) in scenario['tests'].items():
                if k not in DISABLED_TESTS:
                    yield SPFItem.from_parent(self, name=f'{idx}_{k}', scenario=scenario, case=v)
            idx += 1


class SPFItem(pytest.Item):
    def __init__(self, *, scenario, case, **kwargs):
        super().__init__(**kwargs)
        self.scenario = scenario
        self.case = case
        self.dns_proc = None
        self.tmp_path = self.config._tmp_path_factory.mktemp(f'{os.path.basename(self.parent.name)[:-4]}-{self.name}')

    def setup(self):
        self.dns_port = openport(10053)

        devnull = open(os.devnull, 'w')
        self.dns_proc = subprocess.Popen(
            [
                Path(__file__).parent / 'dns/dns_server.py',
                '--port', str(self.dns_port),
                '--zone-data', json.dumps(self.scenario['zonedata']),
            ],
            stdout=devnull,
            stderr=devnull,
        )

        # Wait for the DNS server to be available
        attempt = 0
        while True:
            time.sleep(0.1)
            attempt += 1
            try:
                socket.create_connection(('localhost', self.dns_port), 0.1)
            except socket.error:
                if attempt > 10:
                    raise
            else:
                return

    def runtest(self):
        binpath = os.path.dirname(os.path.realpath(self.parent.path))
        binpath = os.path.realpath(os.path.join(binpath, '..', 'simspf'))

        conf = {
            'core': {
                'dns': {
                    'host': '127.0.0.1',
                    'port': self.dns_port,
                    'timeout': 0.1,
                }
            },
            'receive': {
                'spf': {
                    'query_limit': 10,
                },
            },
        }

        res = subprocess.run(
            [
                binpath,
                '-U', json.dumps(conf),
                self.case['mailfrom'],
                self.case['host'],
                self.case['helo'],
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        expected = self.case['result']
        actual = res.stdout.rstrip().replace('SPF result: ', '')

        if isinstance(expected, list):
            assert actual in expected
            if actual != expected[0]:
                warnings.warn(f'{expected[0]} is preferred over {actual}')
        else:
            assert actual == expected

    def teardown(self):
        if self.dns_proc:
            self.dns_proc.terminate()
