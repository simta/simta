#!/usr/bin/env python3

import smtplib
import socket
import time

import pytest


def test_proxy_v1(simta):
    conn = socket.create_connection(('localhost', simta['port']))
    conn.sendall(b'PROXY TCP4 127.0.0.2 127.0.0.3 40045 10025\r\n')
    response = conn.recv(4096)
    conn.close()
    # 127.0.0.2 has invalid reverse DNS, so it should be denied
    assert response[:3] == b'421'
    assert b'denied by local policy' in response


def test_proxy_v2(simta):
    conn = socket.create_connection(('localhost', simta['port']))
    conn.sendall(b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x0C\x00\x7F\x00\x00\x02\x7F\x00\x00\x03\x52\x51\x27\x29')
    response = conn.recv(4096)
    conn.close()
    # 127.0.0.2 has invalid reverse DNS, so it should be denied
    assert response[:3] == b'421'
    assert b'denied by local policy' in response


def test_proxy_badheader(simta):
    startts = time.time()
    conn = socket.create_connection(('localhost', simta['port']))
    conn.sendall(b'EHLO itsanevilclient\n')
    response = conn.recv(4096)
    conn.close()
    duration = time.time() - startts
    assert response[:3] == b'421'
    assert b'Local error in processing' in response
    assert duration < 1


def test_proxy_timeout(simta):
    startts = time.time()
    with pytest.raises(smtplib.SMTPConnectError) as e:
        smtp = smtplib.SMTP('localhost', simta['port'])
    duration = time.time() - startts
    assert e.value.smtp_code == 421
    assert b'Local error in processing' in e.value.smtp_error
    assert duration > 1
    assert duration < 3
