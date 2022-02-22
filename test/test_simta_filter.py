#!/usr/bin/env python3

import smtplib

import pytest


def test_filter(tmp_path, smtp, testmsg):
    smtp.sendmail(
        'testsender@example.com',
        'testrcpt@example.com',
        testmsg.as_string(),
    )
    assert tmp_path.joinpath('filterenv').exists()


def test_filter_tempfail(tmp_path, smtp, testmsg):
    with pytest.raises(smtplib.SMTPDataError) as e:
        smtp.sendmail(
            'testsender@example.com',
            'testrcpt@example.com',
            testmsg.as_string(),
        )
    assert e.value.smtp_code == 451
    assert e.value.smtp_error == b'Message Tempfailed: tempfailing message'


def test_filter_tempfail_quiet(tmp_path, smtp, testmsg):
    with pytest.raises(smtplib.SMTPDataError) as e:
        smtp.sendmail(
            'testsender@example.com',
            'testrcpt@example.com',
            testmsg.as_string(),
        )
    assert e.value.smtp_code == 451
    assert e.value.smtp_error == b'Message Tempfailed: denied by local policy'


def test_filter_reject(tmp_path, smtp, testmsg):
    with pytest.raises(smtplib.SMTPDataError) as e:
        smtp.sendmail(
            'testsender@example.com',
            'testrcpt@example.com',
            testmsg.as_string(),
        )
    assert e.value.smtp_code == 554
    assert e.value.smtp_error == b'Message Failed: rejecting message'


def test_filter_reject_quiet(tmp_path, smtp, testmsg):
    with pytest.raises(smtplib.SMTPDataError) as e:
        smtp.sendmail(
            'testsender@example.com',
            'testrcpt@example.com',
            testmsg.as_string(),
        )
    assert e.value.smtp_code == 554
    assert e.value.smtp_error == b'Message Failed: denied by local policy'
