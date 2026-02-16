#!/usr/bin/env python3

import smtplib

from inline_snapshot import snapshot


def test_tls_starttls(smtp):
    smtp.ehlo()
    assert smtp.esmtp_features == snapshot({'8bitmime': '', 'size': '104857600', 'starttls': ''})
    smtp.starttls()
    smtp.ehlo()
    assert smtp.esmtp_features == snapshot({'8bitmime': '', 'size': '104857600', 'auth': ' PLAIN'})


def test_tls_legacy(simta):
    smtp = smtplib.SMTP_SSL('localhost', simta['legacy_port'])
    smtp.ehlo()
    assert smtp.esmtp_features == snapshot({'8bitmime': '', 'size': '104857600', 'auth': ' PLAIN'})
    smtp.quit()
