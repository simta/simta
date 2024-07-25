#!/usr/bin/env python3

import smtplib


def test_tls_starttls(smtp):
    smtp.ehlo()
    assert 'starttls' in smtp.esmtp_features
    smtp.starttls()
    smtp.ehlo()
    assert 'starttls' not in smtp.esmtp_features


def test_tls_legacy(simta):
    smtp = smtplib.SMTP_SSL('localhost', simta['legacy_port'])
    smtp.ehlo()
    assert 'starttls' not in smtp.esmtp_features
    assert smtp.esmtp_features['auth'] == ' PLAIN'
    smtp.quit()
