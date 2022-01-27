#!/usr/bin/env python3

def test_filter(tmp_path, smtp, testmsg):
    smtp.sendmail(
        'testsender@example.com',
        'testrcpt@example.com',
        testmsg.as_string(),
    )
    assert tmp_path.joinpath('filterenv').exists()
