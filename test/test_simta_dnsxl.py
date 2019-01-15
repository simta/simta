import smtplib
import time

import pytest

def skip_if_missing(dep):
    if not dep['enabled']:
        pytest.skip(dep['skip_reason'])

def test_dnsbl(simta, dnsserver):
    skip_if_missing(dnsserver)
    with pytest.raises(smtplib.SMTPConnectError) as e:
        smtp = smtplib.SMTP('localhost', simta['port'])
    assert e.value.smtp_code == 554
    assert 'Access denied for IP 127.0.0.1: i see you' in e.value.smtp_error


def test_dnsbl_nomessage(simta, dnsserver):
    skip_if_missing(dnsserver)
    with pytest.raises(smtplib.SMTPConnectError) as e:
        smtp = smtplib.SMTP('localhost', simta['port'])
    assert e.value.smtp_code == 554
    assert 'Access denied for IP 127.0.0.1: default message' in e.value.smtp_error


def test_dnsbl_return(smtp, dnsserver):
    skip_if_missing(dnsserver)
    smtp.ehlo()


def test_dnsbl_logonly(smtp, dnsserver):
    skip_if_missing(dnsserver)
    smtp.ehlo()


def test_dnsal(smtp, dnsserver):
    skip_if_missing(dnsserver)
    smtp.ehlo()

def test_mailbl(smtp, dnsserver):
    skip_if_missing(dnsserver)
    smtp.ehlo()
    res = smtp.docmd('MAIL FROM:<user@example.com>')
    assert res[0] == 250
    res = smtp.docmd('MAIL FROM:<BadUser@example.com>')
    assert res[0] == 550
