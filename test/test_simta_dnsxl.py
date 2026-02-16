#!/usr/bin/env python3

import smtplib

import pytest

from inline_snapshot import snapshot


def test_dnsbl(simta, dnsserver):
    with pytest.raises(smtplib.SMTPConnectError) as e:
        smtplib.SMTP('localhost', simta['port'])
    assert e.value.smtp_code == 554
    assert e.value.smtp_error == snapshot(b'<localhost.test> Access denied for IP 127.0.0.1: i see you')


def test_dnsbl_nomessage(simta, dnsserver):
    with pytest.raises(smtplib.SMTPConnectError) as e:
        smtplib.SMTP('localhost', simta['port'])
    assert e.value.smtp_code == 554
    assert e.value.smtp_error == snapshot(b'<localhost.test> Access denied for IP 127.0.0.1: default message')


def test_dnsbl_return(smtp, dnsserver):
    smtp.ehlo()


def test_dnsbl_logonly(smtp, dnsserver):
    smtp.ehlo()


def test_dnsal(smtp, dnsserver):
    smtp.ehlo()


def test_mailbl(smtp, dnsserver):
    smtp.ehlo()
    res = smtp.docmd('MAIL FROM:<user@example.com>')
    assert list(res) == snapshot([250, b'OK'])
    res = smtp.docmd('MAIL FROM:<BadUser@example.com>')
    assert list(res) == snapshot([550, b'local policy: BadUser@example.com'])


def test_mailbl_domain(smtp, dnsserver):
    smtp.ehlo()
    res = smtp.docmd('MAIL FROM:<baduser@example.com>')
    assert list(res) == snapshot([250, b'OK'])
    res = smtp.docmd('MAIL FROM:<user@example.EDU>')
    assert list(res) == snapshot([550, b'local policy: user@example.EDU'])
