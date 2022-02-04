#!/usr/bin/env python3

import smtplib
import subprocess

import pytest


@pytest.fixture
def sasldb(tmp_path):
    res = {
        'user': 'testuser',
        'password': 'cb8091d80959b156f0ddc74192f9b9141935fb1c54d1b1e3e7d3',
        'file': str(tmp_path.joinpath('sasldb')),
    }

    subprocess.run(
        [
            'saslpasswd2',
            '-f', res['file'],
            '-p',
            '-u', 'example.com',
            '-c',
            res['user']
        ],
        text=True,
        input=res['password'],
    )

    return res


def test_authentication_mechlist(smtp, testmsg, sasldb):
    smtp.ehlo()
    assert 'auth' not in smtp.esmtp_features
    smtp.starttls()
    smtp.ehlo()
    assert smtp.esmtp_features['auth'] == ' LOGIN PLAIN'


def test_authentication(smtp, testmsg, sasldb):
    smtp.starttls()
    smtp.login(sasldb['user'], sasldb['password'])
    smtp.sendmail(
        'testsender@example.com',
        'testrcpt@example.com',
        testmsg.as_string(),
    )


def test_authentication_failure(smtp_nocleanup, testmsg, sasldb):
    smtp_nocleanup.starttls()
    with pytest.raises(smtplib.SMTPAuthenticationError):
        smtp_nocleanup.login(sasldb['user'], 'thisismysecurepassword')
