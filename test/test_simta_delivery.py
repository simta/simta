#!/usr/bin/env python3

import email
import json
import time
import os

from mailbox import Maildir

from dirty_equals import IsStr
from inline_snapshot import snapshot


def test_binary(smtp_nocleanup, testmsg, dnsserver, simta):
    smtp_nocleanup.sendmail(
        'testsender@example.com',
        'testrcpt@binary.example.com',
        testmsg.as_string(),
    )
    smtp_nocleanup.quit()
    time.sleep(2)

    for q in ['dead', 'fast', 'slow']:
        assert len(os.listdir(os.path.join(simta['tmpdir'], q))) == 0

    with open(os.path.join(simta['tmpdir'], 'mda_args'), 'r') as f:
        mda_args = json.load(f)

    assert mda_args[2:] == snapshot(
        [
            'testsender@example.com',
            'testrcpt',
            'binary.example.com',
            '$SR',
            '$',
            'S',
            '-S',
            '$DR',
            '',
            '$DDD',
            '$$',
        ]
    )

    with open(os.path.join(simta['tmpdir'], 'mda_msg'), 'r') as f:
        msg = email.message_from_file(f)

    assert msg.items() == snapshot(
        [
            ('Return-Path', '<testsender@example.com>'),
            (
                'Authentication-Results',
                """\
localhost.test; \n\
	iprev=pass policy.iprev=127.0.0.1 (localhost.test);
	spf=none smtp.mailfrom=testsender@example.com;
	dkim=none;
	dmarc=fail header.from=testsender@example.com\
""",
            ),
            ('Received', IsStr),
            ('Content-Type', 'text/plain; charset="us-ascii"'),
            ('MIME-Version', '1.0'),
            ('Content-Transfer-Encoding', '7bit'),
            ('Subject', 'simta test message for test_binary'),
            ('From', 'testsender@example.com'),
            ('To', 'testrcpt@example.com'),
        ]
    )
    assert msg.get_payload() == snapshot('test_binary\n')


def test_smtp(smtp_nocleanup, testmsg, dnsserver, aiosmtpd_server):
    smtp_nocleanup.sendmail(
        'testsender@example.com',
        'testrcpt@smtpd.example.com',
        testmsg.as_string(),
    )
    smtp_nocleanup.quit()

    md = Maildir(aiosmtpd_server['spooldir'])
    count = 0
    while len(md) == 0:
        count += 1
        assert count < 10
        time.sleep(1)
    assert len(md) == 1

    msg = md.get(md.keys()[0])
    assert msg.items() == snapshot(
        [
            (
                'Authentication-Results',
                """\
localhost.test;
	iprev=pass policy.iprev=127.0.0.1 (localhost.test);
	spf=none smtp.mailfrom=testsender@example.com;
	dkim=none;
	dmarc=fail header.from=testsender@example.com\
""",
            ),
            ('Received', IsStr),
            ('Content-Type', 'text/plain; charset="us-ascii"'),
            ('MIME-Version', '1.0'),
            ('Content-Transfer-Encoding', '7bit'),
            ('Subject', 'simta test message for test_smtp'),
            ('From', 'testsender@example.com'),
            ('To', 'testrcpt@example.com'),
            ('X-Peer', IsStr),
            ('X-MailFrom', 'testsender@example.com'),
            ('X-RcptTo', 'testrcpt@smtpd.example.com'),
        ]
    )
    assert msg.get_payload() == snapshot('test_smtp\n')


def test_smtp_noquit(smtp, testmsg, dnsserver, aiosmtpd_server):
    smtp.sendmail(
        'testsender@example.com',
        'testrcpt@smtpd.example.com',
        testmsg.as_string(),
    )

    md = Maildir(aiosmtpd_server['spooldir'])
    count = 0
    while len(md) == 0:
        count += 1
        assert count < 10
        time.sleep(1)
    assert len(md) == 1

    msg = md.get(md.keys()[0])
    assert msg.items() == snapshot(
        [
            (
                'Authentication-Results',
                """\
localhost.test;
	iprev=pass policy.iprev=127.0.0.1 (localhost.test);
	spf=none smtp.mailfrom=testsender@example.com;
	dkim=none;
	dmarc=fail header.from=testsender@example.com\
""",
            ),
            ('Received', IsStr),
            ('Content-Type', 'text/plain; charset="us-ascii"'),
            ('MIME-Version', '1.0'),
            ('Content-Transfer-Encoding', '7bit'),
            ('Subject', 'simta test message for test_smtp_noquit'),
            ('From', 'testsender@example.com'),
            ('To', 'testrcpt@example.com'),
            ('X-Peer', IsStr),
            ('X-MailFrom', 'testsender@example.com'),
            ('X-RcptTo', 'testrcpt@smtpd.example.com'),
        ]
    )
    assert msg.get_payload() == snapshot('test_smtp_noquit\n')


def test_smtp_badtls(smtp_nocleanup, testmsg, dnsserver, aiosmtpd_server):
    smtp_nocleanup.sendmail(
        'testsender@example.com',
        'testrcpt@smtpd.example.com',
        testmsg.as_string(),
    )
    smtp_nocleanup.quit()

    md = Maildir(aiosmtpd_server['spooldir'])
    count = 0
    while len(md) == 0:
        count += 1
        assert count < 10
        time.sleep(1)
    assert len(md) == 1

    msg = md.get(md.keys()[0])
    assert msg.items() == snapshot(
        [
            (
                'Authentication-Results',
                """\
localhost.test;
	iprev=pass policy.iprev=127.0.0.1 (localhost.test);
	spf=none smtp.mailfrom=testsender@example.com;
	dkim=none;
	dmarc=fail header.from=testsender@example.com\
""",
            ),
            ('Received', IsStr),
            ('Content-Type', 'text/plain; charset="us-ascii"'),
            ('MIME-Version', '1.0'),
            ('Content-Transfer-Encoding', '7bit'),
            ('Subject', 'simta test message for test_smtp_badtls'),
            ('From', 'testsender@example.com'),
            ('To', 'testrcpt@example.com'),
            ('X-Peer', IsStr),
            ('X-MailFrom', 'testsender@example.com'),
            ('X-RcptTo', 'testrcpt@smtpd.example.com'),
        ]
    )
    assert msg.get_payload() == snapshot('test_smtp_badtls\n')


def test_smtp_starttls(smtp_nocleanup, testmsg, dnsserver, aiosmtpd_server):
    smtp_nocleanup.starttls()
    smtp_nocleanup.sendmail(
        'testsender@example.com',
        'testrcpt@smtpd.example.com',
        testmsg.as_string(),
    )
    smtp_nocleanup.quit()

    md = Maildir(aiosmtpd_server['spooldir'])
    count = 0
    while len(md) == 0:
        count += 1
        assert count < 10
        time.sleep(1)
    assert len(md) == 1

    msg = md.get(md.keys()[0])
    assert msg.items() == snapshot(
        [
            (
                'Authentication-Results',
                """\
localhost.test;
	iprev=pass policy.iprev=127.0.0.1 (localhost.test);
	spf=none smtp.mailfrom=testsender@example.com;
	dkim=none;
	dmarc=fail header.from=testsender@example.com\
""",
            ),
            ('Received', IsStr),
            ('Content-Type', 'text/plain; charset="us-ascii"'),
            ('MIME-Version', '1.0'),
            ('Content-Transfer-Encoding', '7bit'),
            ('Subject', 'simta test message for test_smtp_starttls'),
            ('From', 'testsender@example.com'),
            ('To', 'testrcpt@example.com'),
            ('X-Peer', IsStr),
            ('X-MailFrom', 'testsender@example.com'),
            ('X-RcptTo', 'testrcpt@smtpd.example.com'),
        ]
    )
    assert msg.get_payload() == snapshot('test_smtp_starttls\n')
    assert 'with ESMTPS' in msg['Received']
