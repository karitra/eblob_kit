"""Tests for eblob_kit.Blob."""

import mock
import pytest

import eblob_kit

from common import OPEN_TO_PATCH


@mock.patch(OPEN_TO_PATCH, new_callable=mock.mock_open)
def test_create_valid(mocked_open):
    """Test IndexFile.create static method with valid path."""
    test_path = 'some/path/to/index.index'
    eblob_kit.IndexFile.create(test_path)

    assert mocked_open.call_count == 1  # 1 call for create index.
    mocked_open.assert_called_with(test_path, 'wb')


@pytest.mark.xfail(raises=RuntimeError)
def test_create_invalid_path():
    """Test IndexFile.create static method with invalid path."""
    eblob_kit.IndexFile.create('')


@pytest.mark.xfail(raises=RuntimeError)
def test_create_incorrect_path():
    """Test IndexFile.create static method with incorrect path."""
    eblob_kit.IndexFile.create('some/path/to/index')


@mock.patch('eblob_kit.IndexFile', autospec=True)
def test_index_managed_close(mocked_index):
    """Test index context manager."""
    mocked_index.create.return_value = mocked_index
    with eblob_kit.managed_index(''):
        pass

    mocked_index.create.return_value = mocked_index
