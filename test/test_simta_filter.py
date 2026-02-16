#!/usr/bin/env python3

import smtplib

import pytest

from dirty_equals import IsStr
from inline_snapshot import snapshot


def test_filter(tmp_path, smtp, testmsg):
    smtp.sendmail(
        'testsender@example.com',
        'testrcpt@example.com',
        testmsg.as_string(),
    )
    with open(tmp_path.joinpath('filterenv'), 'r') as f:
        res = {k: v for k, v in [x.strip().split('=') for x in f.readlines()]}
        assert res == snapshot(
            {
                'SIMTA_PID': IsStr(regex=r'[0-9]+'),
                'SIMTA_DMARC_DOMAIN': 'example.com',
                'SIMTA_DMARC_RESULT': 'reject',
                'SIMTA_REMOTE_HOSTNAME': 'localhost.test',
                'SIMTA_SPF_DOMAIN': 'example.com',
                'PWD': IsStr,
                'SIMTA_DFILE': IsStr,
                'SIMTA_HEADER_FROM': 'testsender@example.com',
                'SIMTA_DKIM_DOMAINS': '',
                'SIMTA_SMTP_MAIL_FROM': 'testsender@example.com',
                'SIMTA_UID': IsStr(regex=r'[0-9A-F]{8}\.[0-9A-F]{1,8}\.[0-9A-F]{1,8}\.[0-9]+'),
                'SIMTA_REVERSE_LOOKUP': '0',
                'SIMTA_CHECKSUM': IsStr(regex=r'[a-f0-9]{40}'),
                'SIMTA_BODY_CHECKSUM': '49d6dcd943e38bdb6cc0355ee12208a389f9312b',
                'SIMTA_CHECKSUM_SIZE': '126',
                'SIMTA_REMOTE_IP': '127.0.0.1',
                'SIMTA_BAD_HEADERS': '1',
                'SHLVL': '1',
                'SIMTA_MID': '',
                'SIMTA_AUTH_ID': '',
                'SIMTA_CID': IsStr(regex=r'[0-9]+'),
                'SIMTA_SMTP_HELO': IsStr,
                'SIMTA_WRITE_BEFORE_BANNER': '0',
                'SIMTA_BODY_CHECKSUM_SIZE': '11',
                'SIMTA_TFILE': IsStr,
                'SIMTA_SPF_RESULT': 'none',
                '_': '/usr/bin/env',
            }
        )


def test_filter_tempfail(tmp_path, smtp, testmsg):
    with pytest.raises(smtplib.SMTPDataError) as e:
        smtp.sendmail(
            'testsender@example.com',
            'testrcpt@example.com',
            testmsg.as_string(),
        )
    assert e.value.smtp_code == 451
    assert e.value.smtp_error == snapshot(b'Message Tempfailed: tempfailing message')


def test_filter_tempfail_quiet(tmp_path, smtp, testmsg):
    with pytest.raises(smtplib.SMTPDataError) as e:
        smtp.sendmail(
            'testsender@example.com',
            'testrcpt@example.com',
            testmsg.as_string(),
        )
    assert e.value.smtp_code == 451
    assert e.value.smtp_error == snapshot(b'Message Tempfailed: denied by local policy')


def test_filter_reject(tmp_path, smtp, testmsg):
    with pytest.raises(smtplib.SMTPDataError) as e:
        smtp.sendmail(
            'testsender@example.com',
            'testrcpt@example.com',
            testmsg.as_string(),
        )
    assert e.value.smtp_code == 554
    assert e.value.smtp_error == snapshot(b'Message Failed: rejecting message')


def test_filter_reject_quiet(tmp_path, smtp, testmsg):
    with pytest.raises(smtplib.SMTPDataError) as e:
        smtp.sendmail(
            'testsender@example.com',
            'testrcpt@example.com',
            testmsg.as_string(),
        )
    assert e.value.smtp_code == 554
    assert e.value.smtp_error == snapshot(b'Message Failed: denied by local policy')
