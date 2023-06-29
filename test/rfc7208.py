#!/usr/bin/env python3

import errno
import json
import os
import re
import socket
import subprocess
import time
import warnings

import pytest

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
    # require DNS data that is not supported by yadifa
    'a-colon-domain',
    'a-colon-domain-ip4mapped',
    'mx-colon-domain',
    'mx-colon-domain-ip4mapped',
    'macro-mania-in-domain',
    # like the above, probably requires switching away from yadifa as
    # the source of test data so that we can force a timeout.
    'txttimeout',
    'nospftxttimeout',
    'alltimeout',
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

        tmpdir = self.tmp_path.joinpath('yadifa')
        tmpdir.mkdir()
        for subdir in ['keys', 'log', 'xfr', 'data']:
            tmpdir.joinpath(subdir).mkdir()

        conf = str(tmpdir.joinpath('yadifad.conf'))

        zones = {}
        for (host, values) in self.scenario['zonedata'].items():
            # yadifa only supports a subset of technically valid DNS labels
            if not re.fullmatch(r'[+\.a-zA-Z0-9_-]+', host):
                continue

            zone = '.'.join(host.split('.')[-2:])
            if zone not in zones:
                zones[zone] = {}

            cooked = {}
            for v in values:
                if (v == 'TIMEOUT'):
                    # FIXME
                    continue

                for (t, content) in v.items():
                    if t not in cooked:
                        cooked[t] = []
                    if t in ['SPF', 'TXT']:
                        # FIXME: should this be escaped?
                        cooked[t].append(f'"{content}"')
                    elif t == 'MX':
                        cooked[t].append(f'{content[0]} {content[1]}.')
                    elif t == 'PTR':
                        cooked[t].append(f'{content}.')
                    else:
                        cooked[t].append(content)

            # FIXME: The tests should move most data to TXT, not rely on
            # duplicating SPF entries to TXT.

            if cooked.get('SPF') == ['NONE']:
                cooked.pop('SPF')

            if 'SPF' in cooked and 'TXT' not in cooked:
                cooked['TXT'] = cooked.pop('SPF')

            if cooked.get('TXT') == ['NONE']:
                cooked.pop('TXT')

            zones[zone][f'{host}.'] = cooked

        for (zone, entries) in zones.items():
            zone_file = str(tmpdir.joinpath('data', f'{zone}.zone'))
            with open(zone_file, 'w') as f:
                f.write('$TTL    300\n\n')
                f.write('@               IN  SOA localhost.test.     simta.test. (\n')
                f.write('                            1\n')
                f.write('                            300\n')
                f.write('                            300\n')
                f.write('                            6000\n')
                f.write('                            30\n')
                f.write('                            )\n')
                f.write('                    NS  localhost.test.\n\n')
                for (host, values) in entries.items():
                    for (t, content) in values.items():
                        for c in content:
                            if content == 'NONE':
                                continue
                            f.write(f'{host} {t} {c}\n')

        with open(conf, 'w') as f:
            f.write('<main>\n')
            f.write(f'    port {self.dns_port}\n')
            f.write(f'    pidfile {os.path.join(tmpdir, "pid")}\n')
            f.write(f'    datapath {os.path.join(tmpdir, "data")}\n')
            f.write(f'    keyspath {os.path.join(tmpdir, "keys")}\n')
            f.write(f'    logpath {os.path.join(tmpdir, "log")}\n')
            f.write(f'    xfrpath {os.path.join(tmpdir, "xfr")}\n')
            f.write('</main>\n')
            for zone in zones:
                f.write('<zone>\n')
                f.write(f'    domain {zone}\n')
                f.write(f'    file {zone}.zone\n')
                f.write('    type master\n')
                f.write('</zone>\n')

        devnull = open(os.devnull, 'w')
        try:
            self.dns_proc = subprocess.Popen(['yadifad', '-c', conf], stdout=devnull, stderr=devnull)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            pytest.skip('yadifad not found')
            return

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
