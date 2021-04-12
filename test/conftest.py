#!/usr/bin/env python3

import errno
import json
import os
import smtplib
import socket
import subprocess
import time

import pytest

from email.mime.text import MIMEText


def pytest_collect_file(parent, path):
    if os.access(str(path), os.X_OK) and path.basename.startswith('cmocka_'):
        return CMockaFile.from_parent(parent, fspath=path)


class CMockaFile(pytest.File):
    def collect(self):
        out = subprocess.run(
            str(self.fspath),
            env={
                'CMOCKA_MESSAGE_OUTPUT': 'TAP',
            },
            capture_output=True,
            text=True,
        )
        lines = out.stdout.splitlines()
        plan = lines[0].split('..')
        if len(plan) != 2:
            yield(CMockaItem.from_parent(self, line='not ok - cmocka', output=out.stdout))
            plan = ('', '0')

        count = 0
        for line in lines[1:]:
            if not line.startswith('ok') and not line.startswith('not ok'):
                continue
            count += 1
            yield CMockaItem.from_parent(self, line=line, output=out.stdout)

        if count != int(plan[1]):
            yield(CMockaItem.from_parent(self, line='not ok - cmocka_tap_plan', output=out.stdout))


class CMockaItem(pytest.Item):
    def __init__(self, parent, line, output=None):
        name = line.split(' - ')[1]
        super(CMockaItem, self).__init__(name, parent)
        self.line = line
        self.output = output

    def runtest(self):
        if self.line.startswith('not ok'):
            raise CMockaException(self)

    def repr_failure(self, excinfo):
        if isinstance(excinfo.value, CMockaException):
            return self.output


class CMockaException(Exception):
    """ custom exception """


def openport(port):
    # Find a usable port by iterating until there's an unconnectable port
    while True:
        try:
            socket.create_connection(('localhost', port), 0.1)
            port += 1
            if port > 65535:
                raise ValueError("exhausted TCP port range without finding a free one")
        except socket.error:
            return(port)


@pytest.fixture(scope="session")
def dnsserver(tmp_path_factory):
    port = openport(10053)

    tmpdir = str(tmp_path_factory.mktemp('yadifa'))
    for subdir in ['keys', 'log', 'xfr']:
        os.mkdir(os.path.join(tmpdir, subdir))

    conf = os.path.join(tmpdir, 'yadifad.conf')
    datadir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dns')

    with open(conf, 'w') as f:
        f.write('<main>\n')
        f.write('    port {}\n'.format(port))
        f.write('    pidfile {}\n'.format(os.path.join(tmpdir, 'pid')))
        f.write('    datapath {}\n'.format(datadir))
        f.write('    keyspath {}\n'.format(os.path.join(tmpdir, 'keys')))
        f.write('    logpath {}\n'.format(os.path.join(tmpdir, 'log')))
        f.write('    xfrpath {}\n'.format(os.path.join(tmpdir, 'xfr')))
        f.write('</main>\n')
        f.write('<zone>\n')
        f.write('    domain test\n')
        f.write('    file test.zone\n')
        f.write('    type master\n')
        f.write('</zone>\n')
        f.write('<zone>\n')
        f.write('    domain arpa\n')
        f.write('    file arpa.zone\n')
        f.write('    type master\n')
        f.write('</zone>\n')
        f.write('<zone>\n')
        f.write('    domain example.com\n')
        f.write('    file example.com.zone\n')
        f.write('    type master\n')
        f.write('</zone>\n')
        f.write('<zone>\n')
        f.write('    domain example.edu\n')
        f.write('    file example.edu.zone\n')
        f.write('    type master\n')
        f.write('</zone>\n')

    result = {
        'enabled': True,
        'port': port,
    }

    devnull = open(os.devnull, 'w')
    dns_proc = None
    try:
        dns_proc = subprocess.Popen(['yadifad', '-c', conf], stdout=devnull, stderr=devnull)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
        result['enabled'] = False
        result['skip_reason'] = 'yadifad not found'

    yield(result)

    if dns_proc:
        dns_proc.terminate()


@pytest.fixture
def req_dnsserver(dnsserver):
    if not dnsserver['enabled']:
        pytest.skip(dnsserver['skip_reason'])


@pytest.fixture(scope='session')
def ldapserver():
    server = os.environ.get('LDAP_SERVER')
    if server:
        return {
            'enabled': True,
            'uri': server,
        }
    return {
        'enabled': False,
        'skip_reason': 'Environment variable LDAP_SERVER is not set',
    }


@pytest.fixture
def req_ldapserver(ldapserver):
    if not ldapserver['enabled']:
        pytest.skip(ldapserver['skip_reason'])


@pytest.fixture()
def tool_path(scope='session'):
    def _tool_path(tool):
        binpath = os.path.dirname(os.path.realpath(__file__))
        binpath = os.path.join(binpath, '..', tool)
        return os.path.realpath(binpath)
    return _tool_path


@pytest.fixture
def simta_config(request, tmp_path):
    # Find config files to include
    includes = []
    base_path = os.path.join(request.fspath.dirname, 'files')
    for candidate in [
        request.fspath.basename,    # test file
        request.function.__name__,  # test function
    ]:
        fname = os.path.join(base_path, '.'.join([candidate, 'conf']))
        if os.path.isfile(fname):
            includes.append(fname)

    config_file = os.path.join(str(tmp_path), 'simta.conf')

    base_config = {
        'core': {
            'base_dir': str(tmp_path),
            'user': '',
            'debug_level': 7
        },
    }

    if 'filter' in request.fspath.basename:
        base_config['receive'] = {
            'data': {
                'content_filter': {
                    'path': os.path.join(base_path, 'test_filter'),
                }
            }
        }

    with open(config_file, 'w') as f:
        # Strip the surrounding {} so that libucl doesn't put the includes
        # outside the top-level object.
        f.write(json.dumps(base_config, sort_keys=True, indent=4)[1:-1])
        f.write('\n')

        for inc in includes:
            f.write('.include(priority=1, duplicate=merge) "{}"\n'.format(inc))

        f.write('.include(try=true, priority=5) "{}/dynamic.conf"\n'.format(str(tmp_path)))

    return config_file


@pytest.fixture
def simta(request, dnsserver, simta_config, tmp_path, tool_path):
    port = openport(10025)

    for spool in ['command', 'dead', 'etc', 'fast', 'local', 'slow']:
        os.mkdir(os.path.join(str(tmp_path), spool))

    daemon_config = {}
    daemon_config['receive'] = {
        'ports': [port],
    }

    if dnsserver['enabled']:
        daemon_config['core'] = {
            'dns': {
                'host': '127.0.0.1',
                'port': dnsserver['port'],
            }
        }

    binargs = [
        tool_path('simta'),
        '-D',
        '-f', simta_config,
        '-U', json.dumps(daemon_config),
    ]

    simta_proc = subprocess.Popen(binargs)
    running = False
    i = 0
    while not running:
        i += 1
        try:
            socket.create_connection(('localhost', port), 0.1)
            running = True
        except socket.error:
            if i > 20:
                raise
            time.sleep(0.1)

    yield({'port': port, 'tmpdir': str(tmp_path)})

    simta_proc.terminate()


@pytest.fixture
def smtp(smtp_nocleanup):
    yield smtp_nocleanup
    smtp_nocleanup.quit()


@pytest.fixture
def smtp_nocleanup(simta):
    return smtplib.SMTP('localhost', simta['port'])


@pytest.fixture
def testmsg(request):
    msg = MIMEText(request.function.__name__)
    msg['Subject'] = 'simta test message for {}'.format(request.function.__name__)
    msg['From'] = 'testsender@example.com'
    msg['To'] = 'testrcpt@example.com'
    return msg


@pytest.fixture
def run_simsrs(simta_config, tool_path):
    def _run_simsrs(address):
        res = subprocess.run(
            [
                tool_path('simsrs'),
                '-f', simta_config,
                address,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return res.stdout.rstrip()
    return _run_simsrs
