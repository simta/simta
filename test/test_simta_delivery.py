#!/usr/bin/env python3

import email
import json
import time
import os

from mailbox import Maildir


def test_binary(smtp_nocleanup, testmsg, req_dnsserver, simta):
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

    assert mda_args[2:] == [
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

    with open(os.path.join(simta['tmpdir'], 'mda_msg'), 'r') as f:
        msg = email.message_from_file(f)

    assert msg.get_payload() == 'test_binary\n'
    assert msg['Subject'] == 'simta test message for test_binary'
    assert msg['Return-Path'] == '<testsender@example.com>'
    assert msg['From'] == 'testsender@example.com'
    assert msg['To'] == 'testrcpt@example.com'


def test_smtp(smtp_nocleanup, testmsg, req_dnsserver, aiosmtpd_server):
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
    assert msg.get_payload() == 'test_smtp\n'
    assert msg['X-MailFrom'] == 'testsender@example.com'
    assert msg['X-RcptTo'] == 'testrcpt@smtpd.example.com'


def test_smtp_noquit(smtp, testmsg, req_dnsserver, aiosmtpd_server):
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
    assert msg.get_payload() == 'test_smtp_noquit\n'
    assert msg['X-MailFrom'] == 'testsender@example.com'
    assert msg['X-RcptTo'] == 'testrcpt@smtpd.example.com'


def test_smtp_badtls(smtp_nocleanup, testmsg, req_dnsserver, aiosmtpd_server):
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
    assert msg.get_payload() == 'test_smtp_badtls\n'
    assert msg['X-MailFrom'] == 'testsender@example.com'
    assert msg['X-RcptTo'] == 'testrcpt@smtpd.example.com'


def test_smtp_starttls(smtp_nocleanup, testmsg, req_dnsserver, aiosmtpd_server):
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
    assert msg.get_payload() == 'test_smtp_starttls\n'
    assert msg['X-MailFrom'] == 'testsender@example.com'
    assert msg['X-RcptTo'] == 'testrcpt@smtpd.example.com'
    assert 'with ESMTPS' in msg['Received']
