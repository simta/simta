#!/usr/bin/env python3

import subprocess


def test_config(simta_config, tool_path):
    # This just tests the schema of the embedded config
    subprocess.run(
        [
            tool_path('simta'),
            '-f', simta_config,
            '-c',
        ],
        capture_output=True,
        text=True,
    )


def test_config_invalid(simta_config, tool_path):
    res = subprocess.run(
        [
            tool_path('simta'),
            '-f', simta_config,
            '-c'
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0
    assert "validation failure: object has non-allowed property foo" in res.stderr
