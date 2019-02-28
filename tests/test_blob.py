"""Tests for eblob_kit.Blob."""

import mock
import pytest

import eblob_kit

from common import DATA_SORTED_SUFFIX
from common import INDEX_SORTED_SUFFIX
from common import OPEN_TO_PATCH


@mock.patch('os.path.exists', return_value=True)
@mock.patch(OPEN_TO_PATCH, new_callable=mock.mock_open)
def test_create_valid(mocked_open, mocked_exists):
    """Test Blob.create static method with valid path."""
    test_path = 'some/path/to/blob'
    eblob_kit.Blob.create(test_path)

    assert mocked_open.call_count == 3  # 1 call for create index, 1 for open index, 1 for open data.
    assert mocked_exists.call_count == 3  # 1 call for Blob, 2 for DataFile

    mocked_exists.assert_has_calls([
        mock.call(test_path + INDEX_SORTED_SUFFIX),
        mock.call(test_path + DATA_SORTED_SUFFIX),
        mock.call(test_path + INDEX_SORTED_SUFFIX),
    ])

    mocked_open.assert_called_with(test_path, 'wb')


@pytest.mark.xfail(raises=IOError)
def test_create_incorrect_path():
    """Test Blob.create static method with incorrect path."""
    eblob_kit.Blob.create('')
