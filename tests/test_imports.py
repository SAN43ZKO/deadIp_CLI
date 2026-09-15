def test_package_imports():
    import deadip
    assert deadip.__version__


def test_cli_imports():
    from deadip.cli import app
    assert app is not None
