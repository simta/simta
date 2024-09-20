#!/usr/bin/env python3

import socket

import pytest


@pytest.mark.parametrize(
    'cmd',
    [
        '',
        'NXCMD',
        'NXCMD with parameters',
    ]
)
def test_bad_command(smtp, cmd):
    res = smtp.docmd(cmd)
    assert res[0] == 500
    assert res[1] == b'Command unrecognized'


@pytest.mark.parametrize(
    'cmd',
    [
        b'\x80\r\n',
        b'\xe5\xb9\xb4\r\n',
        b'MAIL FROM:<foo@example.edu>\0@example.com>\r\n',
        b'MAIL FROM:<foo@example.edu>\nRCPT TO:<foo@example.com>\r\n',
    ]
)
def test_bad_command_chars(simta, cmd):
    conn = socket.create_connection(('localhost', simta['port']))
    conn.settimeout(5)
    conn.recv(4096)
    conn.sendall(cmd)
    response = conn.recv(4096).splitlines()
    assert response[0] == b'500 syntax error - invalid character'
    conn.close()


@pytest.mark.parametrize(
    'cmd',
    [
        'VRFY foo@example.com',
        'EXPN group',
    ]
)
def test_unimplemented_command(smtp, cmd):
    res = smtp.docmd(cmd)
    assert res[0] == 502
    assert res[1] == b'Command not implemented'
