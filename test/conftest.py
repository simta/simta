#!/usr/bin/env python3

import datetime
import json
import os
import smtplib
import socket
import subprocess
import sys
import time

import pytest

from email.mime.text import MIMEText
from pathlib import Path

try:
    import aiosmtpd     # noqa: F401
    HAS_AIOSMTPD = True
except ImportError:
    HAS_AIOSMTPD = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


pytest_plugins = ['cmocka', 'rfc7208']

PASSWD_CONTENTS = '''
postmaster:x:999:999::{tmp_path}/postmaster:/sbin/nologin
testuser:x:1000:1000::{tmp_path}/testuser:/sbin/nologin
forwarduser:x:1001:1001::{tmp_path}:/sbin/nologin
'''

FORWARD_CONTENTS = '''
user@example.com
user@example.edu
'''

ALIAS_CONTENTS = '''
testuser: anotheruser
external: testuser@example.edu
password: testuser@password.example.com
chained: testuser@alias.example.com
group: testuser@alias.example.com, groupuser@example.com
group2-errors: anotheruser
group2: group@alias.example.com
'''


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


@pytest.fixture(scope="session")
def dnsserver():
    port = openport(10053)

    datadir = Path(__file__).parent / 'dns'

    result = {
        'enabled': True,
        'port': port,
    }

    devnull = open(os.devnull, 'w')
    dns_proc = None
    dns_proc = subprocess.Popen([datadir / 'dns_server.py', '--port', str(port)], stdout=devnull, stderr=devnull)

    yield result

    if dns_proc:
        dns_proc.terminate()


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


@pytest.fixture(scope='session')
def tool_path():
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

    config_file = str(tmp_path.joinpath('simta.conf'))

    base_config = {
        'core': {
            'base_dir': str(tmp_path),
            'user': '',
            'debug_level': 7
        },
        'defaults': {
            'red': {
                'deliver': {
                    'local': {
                        'agent': f'{os.path.join(base_path, "test_mda")} {tmp_path} $S $R $D $SR $ S -S $DR "" $DDD $$',
                    }
                }
            }
        }
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
def simta(dnsserver, aiosmtpd_server, simta_config, tmp_path, tool_path, tls_cert):
    port = openport(10025)
    legacy_port = openport(10465)

    for spool in ['command', 'dead', 'etc', 'fast', 'local', 'slow']:
        tmp_path.joinpath(spool).mkdir()

    subprocess.run(
        [
            tool_path('simalias'),
            '-f', simta_config,
        ],
        # FIXME: can we be smarter about when this runs instead of ignoring errors?
        check=False,
    )

    daemon_config = {}
    daemon_config['receive'] = {
        'ports': [port],
        'tls': {
            'certificate': [
                tls_cert['rsa_certificate'],
                tls_cert['ec_certificate'],
            ],
            'key': [
                tls_cert['ec_key'],
                tls_cert['rsa_key'],
            ],
            'ports': [legacy_port],
        },
        'auth': {
            'authn': {
                'sasl': {
                    'sasldb_path': str(tmp_path.joinpath('sasldb')),
                }
            }
        },
    }
    daemon_config['defaults'] = {
        'red': {
            'deliver': {
                'connection': {
                    'port': aiosmtpd_server['port'],
                }
            }
        }
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
        # change hostname to avoid loop detection when connecting to aiosmtpd
        '-h', 'localhost.test',
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

    yield {'port': port, 'legacy_port': legacy_port, 'tmpdir': str(tmp_path)}

    simta_proc.terminate()


@pytest.fixture
def tls_cert(tmp_path):
    if not HAS_CRYPTOGRAPHY:
        pytest.skip('cryptography not installed')
        return

    keydata = {
        'rsa': rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        ),
        'ec': ec.generate_private_key(ec.SECP384R1()),
    }

    retval = {}

    for ctype in ['rsa', 'ec']:
        private_key = keydata[ctype]
        public_key = private_key.public_key()

        builder = x509.CertificateBuilder(
            ).subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'localhost')])
            ).issuer_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'localhost')])
            ).not_valid_before(
                datetime.datetime.today() - datetime.timedelta(days=1)
            ).not_valid_after(
                datetime.datetime.today() + datetime.timedelta(days=1)
            ).serial_number(
                x509.random_serial_number()
            ).public_key(
                public_key
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u'localhost')]),
                critical=False,
            )

        cert = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        key_path = str(tmp_path.joinpath(f'cert.{ctype}.key'))
        cert_path = str(tmp_path.joinpath(f'cert.{ctype}.crt'))

        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        retval[f'{ctype}_key'] = key_path
        retval[f'{ctype}_certificate'] = cert_path

    return retval


@pytest.fixture
def aiosmtpd_server(request, tmp_path, tls_cert):
    if not HAS_AIOSMTPD:
        pytest.skip('aiosmtpd not available')
        return

    port = openport(10125)
    spooldir = str(tmp_path.joinpath('aiosmtpd'))

    binargs = [
        sys.executable,
        '-m', 'aiosmtpd',
        '-n',
        '-l', ':{}'.format(port),
        '-c', 'aiosmtpd.handlers.Mailbox', spooldir,
        '--tlscert', tls_cert['rsa_certificate'],
        '--tlskey', tls_cert['rsa_key'],
    ]

    if 'badtls' in request.function.__name__:
        binargs.append('--no-requiretls')

    smtpd_proc = subprocess.Popen(binargs)
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

    yield {'port': port, 'spooldir': spooldir}

    smtpd_proc.terminate()


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


@pytest.fixture
def expansion_config(simta_config, request, tmp_path, ldapserver):
    passwd_file = str(tmp_path.joinpath('passwd'))
    alias_file = str(tmp_path.joinpath('alias'))
    with open(passwd_file, 'w') as f:
        f.write(PASSWD_CONTENTS.format(tmp_path=tmp_path))

    with open(str(tmp_path.joinpath('.forward')), 'w') as f:
        f.write(FORWARD_CONTENTS)

    with open(alias_file, 'w') as f:
        f.write(ALIAS_CONTENTS)

    config = {}
    config['domain'] = {
        'password.example.com': {
            'rule': [
                {
                    'type': 'password',
                },
            ]
        },
        'alias.example.com': {
            'rule': [
                {
                    'type': 'alias',
                }
            ]
        },
        'srs.example.com': {
            'rule': [
                {
                    'type': 'srs',
                }
            ]
        },
    }

    config['defaults'] = {
        'red_rule': {
            'alias': {
                'path': alias_file,
            },
            'password': {
                'path': passwd_file,
            },
        }
    }

    if 'subaddress' in request.function.__name__:
        config['defaults']['red_rule']['expand'] = {
            'subaddress_separators': '+=',
        }
    else:
        config['defaults']['red_rule']['expand'] = {
            'subaddress_separators': '',
        }

    if ldapserver['enabled']:
        # This is here to guard against a regression in the LDAP object caching,
        # so it deliberately uses a nonexistent search base and is not useful
        # in tests.
        config['domain']['unusedldap.example.com'] = {
            'rule': [
                {
                    'type': 'ldap',
                    'ldap': {
                        'uri': ldapserver['uri'],
                        'attributes': {
                            'forwarding': 'mailForwardingAddress',
                            'autoreply': 'onVacation',
                        },
                        'search': [
                            {
                                'uri': 'ldap:///ou=Nothing,dc=example,dc=com?*?sub?cn=%25s',
                                'type': 'all',
                            },
                        ],
                        'autoreply': {
                            'host': 'notvacation.mail.example.com',
                        },
                    },
                }
            ]
        }
        config['domain']['example.com'] = {
            'expand': {
                'permit_subdomains': True,
            }
        }
        config['domain']['ldap.example.com'] = {
            'rule': [
                {
                    'type': 'ldap',
                    'ldap': {
                        'uri': ldapserver['uri'],
                        'attributes': {
                            'permitted_senders': 'moderator',
                            'moderators': 'moderator',
                        },
                        'search': [
                            {
                                'uri': 'ldap:///ou=People,dc=example,dc=com?*?sub?uid=%25s',
                                'type': 'user',
                            },
                            {
                                'uri': 'ldap:///ou=People,dc=example,dc=com?*?sub?cn=%25s',
                                'type': 'user',
                            },
                            {
                                'uri': 'ldap:///ou=Groups,dc=example,dc=com?*?sub?cn=%25s %25%25 %25h',
                                'type': 'all',
                            },
                            {
                                'uri': 'ldap:///ou=Groups,dc=example,dc=com?*?sub?cn=%25s',
                                'type': 'all',
                            },
                        ],
                        'autoreply': {
                            'host': 'vacation.mail.example.com',
                        },
                    },
                }
            ]
        }

        # Like ldap.example.com, but with default attributes for moderators
        # and permitted senders
        config['domain']['ldap-new.example.com'] = {
            'rule': [
                {
                    'type': 'ldap',
                    'ldap': {
                        'uri': ldapserver['uri'],
                        'attributes': {
                            'external_address': 'rfc6532mail',
                        },
                        'search': [
                            {
                                'uri': 'ldap:///ou=People,dc=example,dc=com?*?sub?uid=%25s',
                                'type': 'user',
                            },
                            {
                                'uri': 'ldap:///ou=People,dc=example,dc=com?*?sub?cn=%25s',
                                'type': 'user',
                            },
                            {
                                'uri': 'ldap:///ou=Groups,dc=example,dc=com?*?sub?cn=%25s %25%25 %25h',
                                'type': 'all',
                            },
                            {
                                'uri': 'ldap:///ou=Groups,dc=example,dc=com?*?sub?cn=%25s',
                                'type': 'all',
                            },
                        ],
                        'autoreply': {
                            'host': 'vacation.mail.example.com',
                        },
                    },
                }
            ]
        }

        config['domain']['otherldap.domain.example.com'] = {
            'rule': [
                {
                    'type': 'ldap',
                    'associated_domain': 'ldap.example.com',
                    'ldap': {
                        'uri': ldapserver['uri'],
                        'attributes': {
                            'forwarding': 'mailForwardingAddress',
                        },
                        'search': [
                            {
                                'uri': 'ldap:///ou=Groups,dc=example,dc=com?*?sub?cn=%25s',
                                'type': 'all',
                            }
                        ],
                    },
                },
            ],
        }

        config['domain']['control.example.com'] = {
            'rule': [
                {
                    'type': 'ldap',
                    'associated_domain': 'ldap.example.com',
                    'ldap': {
                        'uri': ldapserver['uri'],
                        'search': [
                            {
                                'uri': 'ldap:///ou=Groups,dc=example,dc=com?*?sub?cn=control %25s',
                                'type': 'all',
                                'subsearch': 'ldap:///ou=Groups,dc=example,dc=com?*?sub?(&(cn=control group)(member=%25s))',
                            }
                        ],
                    }
                }
            ]
        }

    with open(str(tmp_path.joinpath('dynamic.conf')), 'w') as f:
        f.write(json.dumps(config)[1:-1])

    return simta_config
