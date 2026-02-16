#!/usr/bin/env python3

import subprocess

import pytest

from inline_snapshot import snapshot


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
    'string,result',
    [
        # \r\n split by the buffer boundary
        [b'0123456\r\n', snapshot(b'0123456\r\n')],
        [b'0123456\r\n78', snapshot(b'0123456\r\n78\r\n')],
        # \r\n after the buffer boundary
        [b'01234567\r\n8', snapshot(b'01234567\r\n8\r\n')],
        # \r\n before the buffer boundary
        [b'012345\r\n678', snapshot(b'012345\r\n678\r\n')],
        # \r\r split by the buffer boundary
        [b'0123456\r\r78', snapshot(b'0123456\r\n\r\n78\r\n')],
        # \n\n split by the buffer boundary
        [b'0123456\n\n78', snapshot(b'0123456\r\n\r\n78\r\n')],
        # \0\0 split by the buffer boundary
        [b'0123456\x00\x0078', snapshot(b'0123456\r\n\r\n78\r\n')],
        # terminal newlines
        [b'0\r\n', snapshot(b'0\r\n')],
        [b'0\r', snapshot(b'0\r\n')],
        [b'0\n', snapshot(b'0\r\n')],
        [b'0\0', snapshot(b'0\r\n')],
        # initial newlines
        [b'\r\n0', snapshot(b'\r\n0\r\n')],
        [b'\r0', snapshot(b'\r\n0\r\n')],
        [b'\n0', snapshot(b'\r\n0\r\n')],
        [b'\x000', snapshot(b'\r\n0\r\n')],
    ],
)
def test_snet_boundary(tool_path, string, result):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-b',
            '4',  # initial yasl allocation will be double this
            '-',
        ],
        check=True,
        capture_output=True,
        input=string,
    )

    assert res.stdout == result


def test_snet_buffer_max(tool_path):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-b',
            '4',
            '-m',
            '8',
            '-',
        ],
        capture_output=True,
        input=b'0123456\n012345678',
    )

    assert res.returncode == 1
    assert res.stdout == snapshot(b'0123456\r\n')
    assert res.stderr == snapshot(b'snet_eof: Cannot allocate memory\n')


@pytest.mark.parametrize(
    'string,result',
    [
        # \r\n split by the buffer boundary
        [b'0123456\r\n78\r\n', snapshot(b'0123456\r\n78\r\n')],
        # \r\n after the buffer boundary
        [b'01234567\r\n8\r\n', snapshot(b'01234567\r\n8\r\n')],
        # \r\n before the buffer boundary
        [b'012345\r\n678\r\n', snapshot(b'012345\r\n678\r\n')],
        # \r\r split by the buffer boundary
        [b'0123456\r\r78\r\n', snapshot(b'0123456\r\r78\r\n')],
        # \n\n split by the buffer boundary
        [b'0123456\n\n78\r\n', snapshot(b'0123456\n\n78\r\n')],
        # no terminal CRLF == not a line
        [b'0123456\r\n78910123456789', snapshot(b'0123456\r\n')],
        # just a lot of empty lines
        [b'\r\n\r\n\r\n\r\n\r\n', snapshot(b'\r\n\r\n\r\n\r\n\r\n')],
        [b'\r\n', snapshot(b'\r\n')],
        # Null
        [b'n\0ull\r\n', snapshot(b'n\x00ull\r\n')],
    ],
)
def test_snet_getline_safe(tool_path, string, result):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-s',
            '-b',
            '4',  # initial yasl allocation will be double this
            '-',
        ],
        check=True,
        capture_output=True,
        input=string,
    )

    assert res.stdout == result


def test_snet_getline_safe_buffer_max(tool_path):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-s',
            '-b',
            '4',
            '-m',
            '8',
            '-',
        ],
        capture_output=True,
        input=b'012345\r\n012345678',
    )

    assert res.returncode == 1
    assert res.stdout == snapshot(b'012345\r\n')
    assert res.stderr == snapshot(b'snet_eof: Cannot allocate memory\n')
