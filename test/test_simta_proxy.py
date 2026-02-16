#!/usr/bin/env python3

import smtplib
import socket
import time

import pytest

from inline_snapshot import snapshot


def test_proxy_v1(simta):
    conn = socket.create_connection(('localhost', simta['port']))
    conn.sendall(b'PROXY TCP4 127.0.0.2 127.0.0.3 40045 10025\r\n')
    response = conn.recv(4096)
    conn.close()
    # 127.0.0.2 has invalid reverse DNS, so it should be denied
    assert response == snapshot(b'421 localhost.test Service not available: closing transmission channel: denied by local policy\r\n')


def test_proxy_v2(simta):
    conn = socket.create_connection(('localhost', simta['port']))
    conn.sendall(b'\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a\x21\x11\x0c\x00\x7f\x00\x00\x02\x7f\x00\x00\x03\x52\x51\x27\x29')
    response = conn.recv(4096)
    conn.close()
    # 127.0.0.2 has invalid reverse DNS, so it should be denied
    assert response == snapshot(b'421 localhost.test Service not available: closing transmission channel: denied by local policy\r\n')


def test_proxy_badheader(simta):
    startts = time.time()
    conn = socket.create_connection(('localhost', simta['port']))
    conn.sendall(b'EHLO itsanevilclient\n')
    response = conn.recv(4096)
    conn.close()
    duration = time.time() - startts
    assert response == snapshot(b'421 localhost.test Local error in processing: closing transmission channel\r\n')
    assert duration < 1


def test_proxy_timeout(simta):
    startts = time.time()
    with pytest.raises(smtplib.SMTPConnectError) as e:
        smtplib.SMTP('localhost', simta['port'])
    duration = time.time() - startts
    assert e.value.smtp_code == snapshot(421)
    assert e.value.smtp_error == snapshot(b'localhost.test Local error in processing: closing transmission channel')
    assert duration > 1
    assert duration < 3
