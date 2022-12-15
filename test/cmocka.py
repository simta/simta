#!/usr/bin/env python3

import os
import subprocess

import pytest


def pytest_collect_file(parent, file_path):
    if os.access(str(file_path), os.X_OK) and file_path.name.startswith('cmocka_'):
        return CMockaFile.from_parent(parent, path=file_path)


class CMockaFile(pytest.File):
    def collect(self):
        out = subprocess.run(
            str(self.fspath),
            cwd=os.path.dirname(self.path),
            env={
                'CMOCKA_MESSAGE_OUTPUT': 'TAP',
            },
            capture_output=True,
            text=True,
        )
        lines = out.stdout.splitlines()
        plan = lines[0].split('..')
        if len(plan) != 2:
            yield CMockaItem.from_parent(self, line='not ok - cmocka', output=out.stdout)
            plan = ('', '0')

        count = 0
        for line in lines[1:]:
            if not line.startswith('ok') and not line.startswith('not ok'):
                continue
            count += 1
            yield CMockaItem.from_parent(self, line=line, output=out.stdout)

        if count != int(plan[1]):
            yield CMockaItem.from_parent(self, line='not ok - cmocka_tap_plan', output=out.stdout)


class CMockaItem(pytest.Item):
    def __init__(self, *, line, output=None, **kwargs):
        name = line.split(' - ')[1]
        super().__init__(name, **kwargs)
        self.line = line
        self.output = output

    def runtest(self):
        if self.line.startswith('not ok'):
            raise CMockaException(self)

    def repr_failure(self, excinfo):
        if isinstance(excinfo.value, CMockaException):
            return self.output


class CMockaException(Exception):
    """ custom exception """
