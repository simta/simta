#!/usr/bin/env python3

import time
import os

from mailbox import Maildir


def test_binary(smtp_nocleanup, testmsg, simta):
    # FIXME: it would be better to actually deliver and check the content
    # that is delivered.
    smtp_nocleanup.sendmail(
        'testsender@example.com',
        'testrcpt@binary.example.com',
        testmsg.as_string(),
    )
    smtp_nocleanup.quit()
    time.sleep(2)
    for q in ['dead', 'fast', 'slow']:
        assert len(os.listdir(os.path.join(simta['tmpdir'], q))) == 0


def test_smtp(smtp_nocleanup, testmsg, req_dnsserver, aiosmtpd):
    smtp_nocleanup.sendmail(
        'testsender@example.com',
        'testrcpt@smtpd.example.com',
        testmsg.as_string(),
    )
    smtp_nocleanup.quit()

    md = Maildir(aiosmtpd['spooldir'])
    count = 0
    while len(md) == 0:
        count += 1
        assert count < 10
        time.sleep(1)
    assert len(md) == 1

    msg = md.get(md.keys()[0])
    assert msg.get_payload() == 'test_smtp\n'
    assert msg['X-MailFrom'] == 'testsender@example.com'
    assert msg['X-RcptTo'] == 'testrcpt@smtpd.example.com'


def test_smtp_noquit(smtp, testmsg, req_dnsserver, aiosmtpd):
    smtp.sendmail(
        'testsender@example.com',
        'testrcpt@smtpd.example.com',
        testmsg.as_string(),
    )

    md = Maildir(aiosmtpd['spooldir'])
    count = 0
    while len(md) == 0:
        count += 1
        assert count < 10
        time.sleep(1)
    assert len(md) == 1

    msg = md.get(md.keys()[0])
    assert msg.get_payload() == 'test_smtp_noquit\n'
    assert msg['X-MailFrom'] == 'testsender@example.com'
    assert msg['X-RcptTo'] == 'testrcpt@smtpd.example.com'


def test_smtp_badtls(smtp_nocleanup, testmsg, req_dnsserver, aiosmtpd):
    smtp_nocleanup.sendmail(
        'testsender@example.com',
        'testrcpt@smtpd.example.com',
        testmsg.as_string(),
    )
    smtp_nocleanup.quit()

    md = Maildir(aiosmtpd['spooldir'])
    count = 0
    while len(md) == 0:
        count += 1
        assert count < 10
        time.sleep(1)
    assert len(md) == 1

    msg = md.get(md.keys()[0])
    assert msg.get_payload() == 'test_smtp_badtls\n'
    assert msg['X-MailFrom'] == 'testsender@example.com'
    assert msg['X-RcptTo'] == 'testrcpt@smtpd.example.com'


def test_smtp_starttls(smtp_nocleanup, testmsg, req_dnsserver, aiosmtpd):
    smtp_nocleanup.starttls()
    smtp_nocleanup.sendmail(
        'testsender@example.com',
        'testrcpt@smtpd.example.com',
        testmsg.as_string(),
    )
    smtp_nocleanup.quit()

    md = Maildir(aiosmtpd['spooldir'])
    count = 0
    while len(md) == 0:
        count += 1
        assert count < 10
        time.sleep(1)
    assert len(md) == 1

    msg = md.get(md.keys()[0])
    assert msg.get_payload() == 'test_smtp_starttls\n'
    assert msg['X-MailFrom'] == 'testsender@example.com'
    assert msg['X-RcptTo'] == 'testrcpt@smtpd.example.com'
    assert 'with ESMTPS' in msg['Received']
