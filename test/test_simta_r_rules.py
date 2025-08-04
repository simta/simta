#!/usr/bin/env python3


def test_r_none(expansion_config, smtp):
    smtp.ehlo('localhost.test')
    res = smtp.mail('')
    assert res[0] == 250
    res = smtp.rcpt('testuser@none.example.com')
    assert res[0] == 551
    assert res[1] == b'User not local to <localhost.test>: please try <none.example.com>'


def test_r_password(expansion_config, smtp):
    smtp.ehlo('localhost.test')
    res = smtp.mail('')
    assert res[0] == 250
    res = smtp.rcpt('testuser@password.example.com')
    assert res[0] == 250

    res = smtp.mail('baduser@password.example.com')
    assert res[0] == 250    # sender is not checked for validity
    res = smtp.rcpt('baduser@password.example.com')
    assert res[0] == 550
    assert res[1] == b'Requested action failed: User not found'


def test_r_alias(expansion_config, smtp):
    smtp.ehlo('localhost.test')
    res = smtp.mail('')
    assert res[0] == 250
    res = smtp.rcpt('testuser@alias.example.com')
    assert res[0] == 250
    res = smtp.rcpt('baduser@alias.example.com')
    assert res[0] == 550
    assert res[1] == b'Requested action failed: User not found'


def test_r_ldap(req_ldapserver, expansion_config, smtp):
    smtp.ehlo('localhost.test')
    res = smtp.mail('')
    assert res[0] == 250
    res = smtp.rcpt('testuser@ldap.example.com')
    assert res[0] == 250
    res = smtp.rcpt('baduser@ldap.example.com')
    assert res[0] == 550
    assert res[1] == b'Requested action failed: User not found'
