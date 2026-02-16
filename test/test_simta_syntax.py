#!/usr/bin/env python3

import socket

import pytest

from inline_snapshot import snapshot


@pytest.mark.parametrize(
    'cmd',
    [
        '',
        'NXCMD',
        'NXCMD with parameters',
    ],
)
def test_bad_command(smtp, cmd):
    res = smtp.docmd(cmd)
    assert list(res) == snapshot([500, b'Command unrecognized'])


@pytest.mark.parametrize(
    'cmd,result',
    [
        [b'\x80\r\n', snapshot([b'500 syntax error - invalid character'])],
        [b'\xe5\xb9\xb4\r\n', snapshot([b'500 syntax error - invalid character'])],
        [b'MAIL FROM:<foo@example.edu>\0@example.com>\r\n', snapshot([b'500 syntax error - invalid character'])],
        [b'MAIL FROM:<foo@example.edu>\nRCPT TO:<foo@example.com>\r\n', snapshot([b'500 syntax error - invalid character'])],
    ],
)
def test_bad_command_chars(simta, cmd, result):
    conn = socket.create_connection(('localhost', simta['port']))
    conn.settimeout(5)
    conn.recv(4096)
    conn.sendall(cmd)
    response = conn.recv(4096).splitlines()
    assert response == result
    conn.close()


@pytest.mark.parametrize(
    'cmd',
    [
        'VRFY foo@example.com',
        'EXPN group',
    ],
)
def test_unimplemented_command(smtp, cmd):
    res = smtp.docmd(cmd)
    assert list(res) == snapshot([502, b'Command not implemented'])
