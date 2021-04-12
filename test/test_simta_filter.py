#!/usr/bin/env python3

import os


def test_filter(tmp_path, smtp, testmsg):
    smtp.sendmail(
        'testsender@example.com',
        'testrcpt@example.com',
        testmsg.as_string(),
    )
    assert os.path.exists(os.path.join(str(tmp_path), 'filterenv'))
