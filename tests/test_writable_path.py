"""Check eblob_kit.is_destination_writable."""
import pytest

from eblob_kit import is_destination_writable


@pytest.mark.parametrize('src_path, dst_path, dst_exist, overwrite, expect', [
    ('/a/b', '/c/d', False, False, True),
    ('/a/b', '/c/d', False, True, True),
    ('/a/b', '/c/d', True, False, False),
    ('/a/b', '/c/d', True, True, True),

    ('/a/b', '/a/b', False, False, False),
    ('/a/b', '/a/b', False, True, False),
    ('/a/b', '/a/b', True, False, False),
    ('/a/b', '/a/b', True, True, False),
])
def test_is_destination_writable(mocker, src_path, dst_path, dst_exist, overwrite, expect):
    """Test for writability check."""
    mocker.patch('os.path.exists', return_value=(src_path == dst_path) or dst_exist)
    mocker.patch('os.path.samefile', return_value=(src_path == dst_path))

    assert is_destination_writable(src_path, dst_path, overwrite) == expect
