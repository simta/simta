import json
import os
import subprocess

import pytest


def test_config(simta_config, real_tmpdir, tool_path):
    # This just tests the schema of the embedded config
    subprocess.check_output([
        tool_path('simta'),
        '-f', simta_config['config_file'],
        '-U', json.dumps(simta_config['config']),
        '-c',
    ])


def test_config_invalid(simta_config, real_tmpdir, tool_path):
    with pytest.raises(subprocess.CalledProcessError) as e:
        subprocess.check_output(
            [
                tool_path('simta'),
                '-f', simta_config['config_file'],
                '-c'
            ],
            stderr=subprocess.STDOUT,
        )
    assert "validation failure: object has non-allowed property foo" in e.value.output
