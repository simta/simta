import pytest


@pytest.mark.parametrize(
    'addr',
    [
        'foo@example.edu',
        'SRS0=gfkgj=fp=subdomain.example.edu=foo@example.edu',
        'SRS0=thisisreallyanopaquestring@example.edu',
    ]
)
def test_srs(run_simsrs, addr):
    srs = run_simsrs(addr)
    unsrs = run_simsrs(srs)
    assert unsrs == addr


def test_srs_reforward(run_simsrs):
    addr = 'SRS1=re2xz=example.com==gfkgj=fp=subdomain.example.edu=foo@example.edu'
    srs = run_simsrs(addr)
    unsrs = run_simsrs(srs)
    assert unsrs == 'SRS0=gfkgj=fp=subdomain.example.edu=foo@example.com'
