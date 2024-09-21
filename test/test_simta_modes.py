#!/usr/bin/env python3

import errno
import smtplib
import socket
import time

import pytest


def send_test(smtp, testmsg):
    smtp.sendmail(
        'testsender@example.com',
        'testrcpt@example.com',
        testmsg.as_string(),
    )


def test_mode_normal(smtp, testmsg):
    smtp.ehlo()
    with pytest.raises(smtplib.SMTPRecipientsRefused):
        send_test(smtp, testmsg)


def test_mode_disabled(simta):
    with pytest.raises(smtplib.SMTPConnectError) as e:
        smtplib.SMTP('localhost', simta['port'])
    assert e.value.smtp_code == 554


def test_mode_global_relay(smtp, testmsg):
    send_test(smtp, testmsg)


def test_mode_tarpit(smtp, testmsg):
    startts = time.time()
    with pytest.raises(smtplib.SMTPDataError) as e:
        send_test(smtp, testmsg)
    assert e.value.smtp_code == 451
    assert time.time() - startts < 1


def test_mode_tarpit_timing(smtp, testmsg):
    startts = time.time()
    with pytest.raises(smtplib.SMTPDataError) as e:
        send_test(smtp, testmsg)
    assert e.value.smtp_code == 451
    assert time.time() - startts > 2.5
    assert time.time() - startts < 5


def test_mode_tempfail(smtp):
    smtp.ehlo()
    res = smtp.docmd('MAIL FROM:<>')
    assert res[0] == 451
    res = smtp.docmd('RCPT TO:<>')
    assert res[0] == 451
    res = smtp.docmd('DATA')
    assert res[0] == 503


def trigger_punishment(smtp):
    res = smtp.docmd('MAIL FROM:<testsender@example.com>')
    assert res[0] == 250
    res = smtp.docmd('RCPT TO:<badrcpt@example.edu>')
    assert res[0] == 551
    res = smtp.docmd('RCPT TO:<badrcpt@example.edu>')
    assert res[0] == 551


def test_punishment_mode_tempfail(smtp, testmsg):
    send_test(smtp, testmsg)
    trigger_punishment(smtp)
    test_mode_tempfail(smtp)


def test_punishment_trigger_mailfrom(smtp, testmsg):
    send_test(smtp, testmsg)
    res = smtp.docmd('MAIL FROM:<me@baddomain.example.com>')
    assert res[0] == 550
    res = smtp.docmd('MAIL FROM:<me@baddomain.example.com>')
    assert res[0] == 550
    test_mode_tempfail(smtp)


def test_punishment_trigger_auth(smtp, testmsg):
    send_test(smtp, testmsg)
    smtp.login('fakeuser', 'fakepassword')
    test_mode_tempfail(smtp)


def test_punishment_trigger_nobanner(simta, testmsg):
    smtp = smtplib.SMTP('localhost', simta['port'])
    test_mode_global_relay(smtp, testmsg)
    smtp.quit()

    startts = time.time()
    conn = socket.create_connection(('localhost', simta['port']))
    conn.settimeout(5)
    conn.sendall(b'EHLO itsanevilclient\r\n')
    response = conn.recv(4096).splitlines()
    assert response[0][:3] == b'220'
    # Sometimes the first recv will get both the banner and the EHLO response.
    # Sometimes it won't.
    if len(response) == 1:
        response = conn.recv(4096)
    else:
        response = response[1]
    assert response[:3] == b'421'
    conn.sendall(b'MAIL FROM:<eviluser@example.com>\r\n')
    with pytest.raises(socket.error) as e:
        while True:
            conn.sendall(b'MAIL FROM:<eviluser@example.com>\r\n')
            response = conn.recv(4096)
    assert e.value.errno in [errno.ECONNRESET, errno.EPIPE]
    assert time.time() - startts > 1
    assert time.time() - startts < 3


def test_punishment_mode_disabled(smtp_nocleanup, testmsg):
    smtp = smtp_nocleanup
    send_test(smtp, testmsg)
    trigger_punishment(smtp)
    res = smtp.docmd('RCPT TO:<badrcpt@example.edu>')
    assert res[0] == 421
    with pytest.raises(smtplib.SMTPServerDisconnected):
        res = smtp.docmd('RCPT TO:<badrcpt@example.edu>')


def test_punishment_mode_tarpit(smtp, testmsg):
    send_test(smtp, testmsg)
    trigger_punishment(smtp)
    smtp.docmd('RSET')
    test_mode_tarpit(smtp, testmsg)
