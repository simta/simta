#!/usr/bin/env python3

import subprocess

import pytest


def test_snet_basic(tool_path):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-',
        ],
        check=True,
        capture_output=True,
        input=b"hello\nworld\r\n\r\n\r\nit's\rya\n\rboi\0snet",
    )

    # snet regularizes all line endings to \r\n
    assert res.stdout == b"hello\r\nworld\r\n\r\n\r\nit's\r\nya\r\n\r\nboi\r\nsnet\r\n"


@pytest.mark.parametrize(
    'test_pair',
    [
        # \r\n split by the buffer boundary
        (b'0123456\r\n', b'0123456\r\n'),
        (b'0123456\r\n78', b'0123456\r\n78\r\n'),
        # \r\n after the buffer boundary
        (b'01234567\r\n8', b'01234567\r\n8\r\n'),
        # \r\n before the buffer boundary
        (b'012345\r\n678', b'012345\r\n678\r\n'),
        # \r\r split by the buffer boundary
        (b'0123456\r\r78', b'0123456\r\n\r\n78\r\n'),
        # \n\n split by the buffer boundary
        (b'0123456\n\n78', b'0123456\r\n\r\n78\r\n'),
        # \0\0 split by the buffer boundary
        (b'0123456\x00\x0078', b'0123456\r\n\r\n78\r\n'),
        # terminal newlines
        (b'0\r\n', b'0\r\n'),
        (b'0\r', b'0\r\n'),
        (b'0\n', b'0\r\n'),
        (b'0\0', b'0\r\n'),
        # initial newlines
        (b'\r\n0', b'\r\n0\r\n'),
        (b'\r0', b'\r\n0\r\n'),
        (b'\n0', b'\r\n0\r\n'),
        (b'\x000', b'\r\n0\r\n'),
    ]
)
def test_snet_boundary(tool_path, test_pair):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-b', '4',  # initial yasl allocation will be double this
            '-',
        ],
        check=True,
        capture_output=True,
        input=test_pair[0],
    )

    assert res.stdout == test_pair[1]


def test_snet_buffer_max(tool_path):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-b', '4',
            '-m', '8',
            '-',
        ],
        capture_output=True,
        input=b'0123456\n012345678',
    )

    assert res.returncode == 1
    assert res.stdout == b'0123456\r\n'
    assert res.stderr == b'snet_eof: Cannot allocate memory\n'


@pytest.mark.parametrize(
    'test_data',
    [
        # \r\n split by the buffer boundary
        b'0123456\r\n78\r\n',
        # \r\n after the buffer boundary
        b'01234567\r\n8\r\n',
        # \r\n before the buffer boundary
        b'012345\r\n678\r\n',
        # \r\r split by the buffer boundary
        b'0123456\r\r78\r\n',
        # \n\n split by the buffer boundary
        b'0123456\n\n78\r\n',
        # no terminal CRLF == not a line
        [b'0123456\r\n78910123456789', b'0123456\r\n'],
        # just a lot of empty lines
        b'\r\n\r\n\r\n\r\n\r\n',
        b'\r\n',
        # Null
        b'n\0ull\r\n',
    ]
)
def test_snet_getline_safe(tool_path, test_data):
    if not isinstance(test_data, list):
        test_data = [test_data, test_data]

    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-s',
            '-b', '4',  # initial yasl allocation will be double this
            '-',
        ],
        check=True,
        capture_output=True,
        input=test_data[0],
    )

    assert res.stdout == test_data[1]


def test_snet_getline_safe_buffer_max(tool_path):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-s',
            '-b', '4',
            '-m', '8',
            '-',
        ],
        capture_output=True,
        input=b'012345\r\n012345678',
    )

    assert res.returncode == 1
    assert res.stdout == b'012345\r\n'
    assert res.stderr == b'snet_eof: Cannot allocate memory\n'
