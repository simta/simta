#!/usr/bin/env python3

import smtplib

import pytest


def test_dnsbl(simta, dnsserver):
    with pytest.raises(smtplib.SMTPConnectError) as e:
        smtplib.SMTP('localhost', simta['port'])
    assert e.value.smtp_code == 554
    assert b'Access denied for IP 127.0.0.1: i see you' in e.value.smtp_error


def test_dnsbl_nomessage(simta, dnsserver):
    with pytest.raises(smtplib.SMTPConnectError) as e:
        smtplib.SMTP('localhost', simta['port'])
    assert e.value.smtp_code == 554
    assert b'Access denied for IP 127.0.0.1: default message' in e.value.smtp_error


def test_dnsbl_return(smtp, dnsserver):
    smtp.ehlo()


def test_dnsbl_logonly(smtp, dnsserver):
    smtp.ehlo()


def test_dnsal(smtp, dnsserver):
    smtp.ehlo()


def test_mailbl(smtp, dnsserver):
    smtp.ehlo()
    res = smtp.docmd('MAIL FROM:<user@example.com>')
    assert res[0] == 250
    res = smtp.docmd('MAIL FROM:<BadUser@example.com>')
    assert res[0] == 550


def test_mailbl_domain(smtp, dnsserver):
    smtp.ehlo()
    res = smtp.docmd('MAIL FROM:<baduser@example.com>')
    assert res[0] == 250
    res = smtp.docmd('MAIL FROM:<user@example.EDU>')
    assert res[0] == 550
