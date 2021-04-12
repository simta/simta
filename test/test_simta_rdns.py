#!/usr/bin/env python3

import socket


def bad_rdns(simta):
    # Use the PROXY protocol so we don't have to try to break RDNS for 127.0.0.1
    conn = socket.create_connection(('localhost', simta['port']))
    conn.sendall(b'PROXY TCP4 127.0.0.2 127.0.0.3 10025 10025\r\n')
    response = conn.recv(4096)
    conn.close()
    return response


def test_rdns_strict(simta):
    response = bad_rdns(simta)
    assert response[:3] == b'421'


def test_rdns_relaxed(simta):
    response = bad_rdns(simta)
    assert response[:3] == b'220'


# FIXME: this only actually tests something when dnsserver is disabled
def test_rdns_chillaxed(smtp):
    smtp.ehlo()
