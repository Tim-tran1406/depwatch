from depwatch import __version__


def test_version_is_set():
    assert __version__


def test_cli_app_imports():
    from depwatch.cli import app

    assert app is not None
