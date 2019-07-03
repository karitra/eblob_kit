"""Test mocks for eblob_kit.BlobRepairer.

TODO(karapuz): implement tests for BlobRepairer methods:
  - fix
  - print_check_report
  - check
  - recover_index
  - recover_blob
  - copy_valid_records

TODO(karapuz): move common patch wrappers to fixture.
TODO(karapuz): complete tests parameters docs.

"""
import mock
import pytest

from eblob_kit import BlobRepairer
from eblob_kit import EllipticsHeader
from eblob_kit import RecordFlags

from common import make_header
from common import OPEN_TO_PATCH


TEST_BLOB_PATH = 'src/path'
TEST_BLOB_PREFIX = 'test_data-0.0'

TEST_DESTINATION_PATH = 'dst/path'

TEST_INDEX_PATH = TEST_BLOB_PATH + '/' + 'test_data-0.0.index'
TEST_INDEX_SORTED_PATH = TEST_BLOB_PATH + '/' + 'test_data-0.0.index.sorted'

TEST_DATA_PATH = TEST_BLOB_PATH + '/' + TEST_BLOB_PREFIX


@pytest.mark.parametrize('header, data_len, check_result', [
    (make_header(data_size=1, disk_size=128), 512, True),
    # Malformed header has empty disk_size.
    (make_header(data_size=1, position=1), 512, False),
    # Malformed header has out of range position (position + disk_size > total data len).
    (make_header(data_size=1, disk_size=128, position=1), 128, False),
    # Malformed header has empty data_size, but it is committed and not removed.
    (make_header(disk_size=128), 512, False),
])
@mock.patch('eblob_kit.IndexFile', autospec=True)
@mock.patch('eblob_kit.DataFile', autospec=True)
@mock.patch('os.path.exists', return_value=True)
def test_check_header_without_flags(_mocked_index,
                                    mocked_data_file,
                                    mocked_exist,
                                    header,
                                    data_len,
                                    check_result):
    """Check generated header whith BlobRepairer.check_header.

    Constructs various headers and check them for validity.

    :param eblob_kit.DiskControl header: header stub.

    """
    # DataFile mock
    mocked_data_file.return_value.__len__.return_value = data_len

    # Blob mock
    blob_repairer = BlobRepairer(TEST_BLOB_PATH)

    assert blob_repairer.check_header(header) == check_result


@pytest.mark.parametrize('flags', [
   RecordFlags.UNCOMMITTED,
   RecordFlags.REMOVED,
   RecordFlags.UNCOMMITTED | RecordFlags.EXTHDR,
   RecordFlags.REMOVED | RecordFlags.EXTHDR,
])
@mock.patch('eblob_kit.IndexFile', autospec=True)
@mock.patch('eblob_kit.DataFile', autospec=True)
@mock.patch('os.path.exists', return_value=True)
def test_check_header_with_flags_nodata_size(_mocked_exists, mocked_data_file, _mocked_index, flags):
    """Tested valid headers with different flags combination.

    :param eblob_kit.RecordFlags flags: bit flags to be used with eblob_kit.DiskControl

    """
    # DataFile mock
    mocked_data_file.return_value.__len__.return_value = 512

    header = make_header(flags=RecordFlags(flags), disk_size=128)

    blob_repairer = BlobRepairer(TEST_BLOB_PATH)
    assert blob_repairer.check_header(header)


@pytest.mark.parametrize('data_size, disk_size, expect', [
    (128, 128, False),
    # 64 below - checksum size
    (128, 128 + EllipticsHeader.size + 64 - 1, False),
    (128, 128 + EllipticsHeader.size + 64, True),
])
@mock.patch('eblob_kit.IndexFile', autospec=True)
@mock.patch('eblob_kit.DataFile', autospec=True)
@mock.patch('os.path.exists', return_value=True)
def test_check_header_with_exthdr_and_datasize(_mocked_exists,
                                               mocked_data_file,
                                               _index_file,
                                               data_size,
                                               disk_size,
                                               expect):
    """Check header with EXTHDR and incorrect data_size.

    Checks for:

      header.data_size + EllipticsHeader.size(48) + checksum_size(64) > header.disk_size

    """
    header = make_header(data_size=data_size, disk_size=disk_size, flags=RecordFlags(RecordFlags.EXTHDR))

    # Return big enough constant to suppress preliminary checks in BlobRepairer.check_header.
    mocked_data_file.return_value.__len__.return_value = 512

    blob_repairer = BlobRepairer(TEST_BLOB_PATH)
    assert blob_repairer.check_header(header) == expect


@pytest.mark.parametrize('position, end, header_position, holes, holes_size, check_header_called',
                         [
                             (0,   3,   0, 1, 3, 1),
                             (0,   1, 100, 1, 1, 1),
                             (1,   3,   1, 1, 2, 1),
                             (5,   6,   6, 1, 1, 1),
                             (5,   5,   5, 0, 0, 0),
                         ])
@mock.patch('eblob_kit.IndexFile', autospec=True)
@mock.patch('eblob_kit.DataFile', autospec=True)
@mock.patch('os.path.exists', return_value=True)
def test_check_hole(_mock_exist,
                    data_mock,
                    _index_mock,
                    mocker,
                    position,
                    end,
                    header_position,
                    holes,
                    holes_size,
                    check_header_called):
    """Check generated DiskControl header with BlobRepairer.check_hole.

    TODO(karapuz): try to move common for all test patch code to BlobRepairer fixture.

    :param int position:
    :param int end:
    :param int header_position:
    :param int holes:
    :param int holes_size:
    :param int check_header_called:

    """
    # DataFile mock
    dummy_header = make_header(position=header_position)
    data_mock.return_value.read_disk_control.return_value = dummy_header

    blob_repairer = BlobRepairer(TEST_BLOB_PATH)
    assert blob_repairer.valid

    mocker.spy(blob_repairer, 'check_header')

    blob_repairer.check_hole(position, end)

    assert blob_repairer.stat.holes == holes
    assert blob_repairer.stat.holes_size == holes_size

    if check_header_called:
        blob_repairer.check_header.assert_called_with(dummy_header)

    assert blob_repairer.check_header.call_count == check_header_called


@pytest.mark.parametrize('header_index, position, headers', [
    (1, 8, [make_header(disk_size=5, position=3), make_header()]),
    (0, 0, [make_header(), make_header()]),
    (1, 11, [make_header(disk_size=5, position=3), make_header()]),
])
@mock.patch('eblob_kit.IndexFile', autospec=True)
@mock.patch('eblob_kit.DataFile', autospec=True)
@mock.patch('os.path.exists', return_value=True)
def test_resolve_mispositioned_record_assert(_mocked_exists,
                                             mocked_data_file,
                                             _index_file_mock,
                                             header_index,
                                             position,
                                             headers):
    """Check for resolve_mispositioned_record fail on assert.

    :param int header_index:
    :param int position:
    :param List[eblob_kit.DiskControl] headers:

    """
    mocked_data_file.return_value.read_disk_control.return_value = make_header()

    blob_repairer = BlobRepairer(TEST_BLOB_PATH)
    assert blob_repairer.valid

    with pytest.raises(AssertionError):
        blob_repairer._index_headers = headers
        blob_repairer.resolve_mispositioned_record(header_index, position, [])


@pytest.mark.parametrize('header_index, position, headers, expect_result', [
    (1, 0, [make_header(), make_header(), ], False),
    (2, 2, [make_header(), make_header(disk_size=1, position=1), make_header(position=2), ], True),
])
@mock.patch('eblob_kit.IndexFile', autospec=True)
@mock.patch('eblob_kit.DataFile', autospec=True)
@mock.patch('os.path.exists', return_value=True)
def test_resolve_mispositioned_record_with_empty_disk_control(_mocked_exists,
                                                              mocked_data_file,
                                                              _mocked_index_file,
                                                              header_index,
                                                              position,
                                                              headers,
                                                              expect_result):
    """Check different combinations of headers sequences.

    Check different combinations of headers sequences with
    BlobRepairer.resolve_mispositioned_record and empty disk control.

    TODO(karapuz): not all branches are tested within:
      eblob_kit.BlobRepairer.resolve_mispositioned_record

    :param int header_index:
    :param int position:
    :param List[eblob_kit.DiskControl] headers:
    :param bool expect_result:

    """
    mocked_data_file.return_value.read_disk_control.return_value = make_header()

    blob_repairer = BlobRepairer(TEST_BLOB_PATH)
    assert blob_repairer.valid

    blob_repairer._index_headers = headers

    assert blob_repairer.resolve_mispositioned_record(header_index, position, []) == expect_result


@pytest.mark.parametrize('header_index, position, disk_control_position', [
    (1, 8, 4),
])
@mock.patch('eblob_kit.IndexFile', autospec=True)
@mock.patch('eblob_kit.DataFile', autospec=True)
@mock.patch('os.path.exists', return_value=True)
def test_resolve_mispositioned_record_with_positioned_disk_control(_mocked_exists,
                                                                   mocked_data_file,
                                                                   _mocked_index_file,
                                                                   header_index,
                                                                   position,
                                                                   disk_control_position):
    """Check different combinations of headers sequences with non empty disk_control.

    TODO(karapuz): add test to this test case.

    :param int header_index:
    :param int position:
    :param int disk_control_position:

    """
    mocked_data_file.return_value.read_disk_control.return_value = make_header(position=disk_control_position)

    blob_repairer = BlobRepairer(TEST_BLOB_PATH)
    assert blob_repairer.valid

    blob_repairer._index_headers = [make_header(disk_size=5, position=3), make_header(position=4), ]

    assert not blob_repairer.resolve_mispositioned_record(header_index, position, [])


@mock.patch('eblob_kit.IndexFile', autospec=True)
@mock.patch('eblob_kit.DataFile', autospec=True)
@mock.patch('os.path.exists', return_value=True)
def test_resolve_mismatch(_mocked_exists, _mocked_data_file, _mocked_index_file):
    """Check generated headers sequence with BlobRepairer.resolve_mismatch."""
    blob_repairer = BlobRepairer(TEST_BLOB_PATH)
    assert blob_repairer.valid

    flags = RecordFlags(0)
    args_list = [make_header(key='', data_size=x, disk_size=2 * x, flags=flags, position=3 * x)
                 for x in xrange(3)]
    blob_repairer.resolve_mismatch(*args_list)

    assert not blob_repairer.valid
    assert blob_repairer.stat.mismatched_headers == [tuple(args_list)[:2]]


@pytest.mark.parametrize('index, is_sorted, valid, malformed_headers', [
    ([make_header(key='b'), make_header(key='a', disk_size=3)],  # Index
     False,  # index sorted.
     False,  # check result valid.
     1, ),
    ([make_header(), make_header(key='a', disk_size=128)],  # Index
     True,  # index sorted.
     False,  # check result valid.
     1, ),
    ([make_header(key='a',
                  disk_size=128,
                  data_size=1,
                  position=1),
      make_header(key='b',
                  disk_size=128,
                  data_size=1,
                  position=2)],
     False,  # index sorted.
     True,  # check result valid.
     0, )
])
@mock.patch('eblob_kit.IndexFile', autospec=True)
@mock.patch('eblob_kit.DataFile', autospec=True)
@mock.patch('os.path.exists', return_value=True)
def test_check_index_valid_size_no_order_error(_mocked_exists,
                                               mocked_data_file,
                                               mocked_index_file,
                                               mocker,
                                               index,
                                               is_sorted,
                                               valid,
                                               malformed_headers):
    """Check generated headers sequence with eblob_kit.BlobRepairer.check_index.

    :param List[eblob_kit.DiskControl] index:
    :param bool is_sorted:
    :param bool valid:
    :param int malformed_headers:

    """
    mocked_index_file.return_value.__iter__.return_value = iter(index)

    type(mocked_index_file.return_value).sorted = mocker.PropertyMock(return_value=is_sorted)

    # Need to set some abstract value in order to make inner
    # check_header return True.
    mocked_data_file.return_value.__len__.return_value = 256

    blob_repairer = BlobRepairer(TEST_BLOB_PATH)

    assert blob_repairer.valid
    assert not blob_repairer.stat.index_order_error

    blob_repairer.check_index(True)

    assert blob_repairer.valid == valid

    assert not blob_repairer.stat.invalid_index_size
    assert not blob_repairer.stat.index_order_error

    assert blob_repairer.stat.index_malformed_headers == malformed_headers


@pytest.mark.parametrize('index, sorted, invalid_index_size, index_order_error', [
    (EOFError(), False, True, False),
    ([make_header(key='b', disk_size=128, data_size=1, position=1),
      make_header(key='a', disk_size=128, data_size=1, position=2)],
     True,  False,  True)
])
@mock.patch('eblob_kit.IndexFile', autospec=True)
@mock.patch('eblob_kit.DataFile', autospec=True)
@mock.patch('os.path.exists', return_value=True)
def test_check_index_non_valid(_mocked_exists,
                               mocked_data_file,
                               mocked_index_file,
                               mocker,
                               index,
                               sorted,
                               invalid_index_size,
                               index_order_error):
    """Check generated headers sequence with eblob_kit.BlobRepairer.check_index.

    TODO(karapuz): add test cases.

    :param List[eblob_kit.DiskControl] index:
    :param bool sorted:
    :param bool invalid_index_size:
    :param bool index_order_error:

    """
    if isinstance(index, Exception):
        mocked_index_file.return_value.__iter__.side_effect = index
    else:
        mocked_index_file.return_value.__iter__.return_value = iter(index)

    type(mocked_index_file.return_value).sorted = mocker.PropertyMock(return_value=sorted)

    # Need to set some abstract value in order to make inner
    # check_header return True.
    mocked_data_file.return_value.__len__.return_value = 256

    blob_repairer = BlobRepairer(TEST_BLOB_PATH)

    assert blob_repairer.valid
    assert not blob_repairer.stat.index_order_error

    blob_repairer.check_index(True)

    assert not blob_repairer.valid
    assert blob_repairer.stat.invalid_index_size == invalid_index_size

    assert blob_repairer.stat.index_order_error == index_order_error

    assert blob_repairer.stat.index_malformed_headers == 0


@pytest.mark.parametrize('callee', [
    BlobRepairer.recover_index,
    BlobRepairer.recover_blob,
    BlobRepairer.copy_valid_records,
])
@mock.patch('eblob_kit.is_destination_writable', return_value=True)
@mock.patch(OPEN_TO_PATCH, new_callable=mock.mock_open)
@mock.patch('eblob_kit.Blob', autospec=True)
def test_fix_destination_writable(mocked_blob,
                                  _mocked_open,
                                  _mocked_is_writable,
                                  callee):
    """Check if destination is writable.

    Checks for `copy_valid_records`, `recover_index` and `recover_blob`.

    """
    mocked_blob.create.return_value = mocked_blob
    mocked_blob.get_index_data_path_tuple.return_value = (None, None)

    type(mocked_blob.return_value.data).path = mock.PropertyMock(return_value='data')

    blob_repairer = BlobRepairer('.')

    if callee == BlobRepairer.recover_index:
        callee(blob_repairer._blob.data, '.')
    else:
        callee(blob_repairer, '.')


@pytest.mark.parametrize('callee', [
    BlobRepairer.recover_index,
    BlobRepairer.recover_blob,
    BlobRepairer.copy_valid_records,
])
@mock.patch('eblob_kit.is_destination_writable', return_value=False)
@mock.patch(OPEN_TO_PATCH, new_callable=mock.mock_open)
@mock.patch('eblob_kit.Blob', autospec=True)
def test_fix_destination_not_writable(mocked_blob,
                                      _mocked_open,
                                      _mocked_is_writable,
                                      callee):
    """Check for exception if destination not writable.

    Checks for `copy_valid_records`, `recover_index` and `recover_blob`.

    """
    type(mocked_blob.return_value.data).path = mock.PropertyMock(return_value='data')

    blob_repairer = BlobRepairer('.')

    with pytest.raises(RuntimeError):
        if callee == BlobRepairer.recover_index:
            callee(blob_repairer._blob.data, '.')
        else:
            callee(blob_repairer, '.')


def test_fix(mocker):
    """Tests for BlobRepairer.fix.

    TODO(karapuz): function test for 'fix' command, following test not completed.

    """
    # IndexFile mock
    index_file_class = mocker.patch('eblob_kit.IndexFile', autospec=True)

    index_header = make_header(key='', data_size=1, disk_size=2, position=3, flags=4)
    index_file_class.return_value.__iter__.return_value = iter([index_header])

    # TODO(karapuz): add test for sorted case
    type(index_file_class.return_value).sorted = mocker.PropertyMock(return_value=False)

    # DataFile mock
    mocker.patch('eblob_kit.DataFile', autospec=True)

    # Blob mock
    mocked_blob = mock.Mock()
    mocked_blob.create.return_value = mocked_blob
    mocked_blob.get_index_data_path_tuple.return_value = (None, None)

    mocker.patch('eblob_kit.Blob.create', return_value=mocked_blob)
    mocker.patch('eblob_kit.is_destination_writable', return_value=True)

    mocker.patch('os.path.exists', return_value=True)

    blob_repairer = BlobRepairer(TEST_BLOB_PATH)

    mocker.spy(blob_repairer, 'check')
    mocker.spy(blob_repairer, 'check_index')
    mocker.spy(blob_repairer, 'print_check_report')

    blob_repairer.fix(TEST_DESTINATION_PATH, noprompt=True)

    # Check the self.check method
    assert blob_repairer.check.call_count == 1
    blob_repairer.check.assert_called_with(verify_csum=True, fast=False)

    assert blob_repairer.check_index.call_count == 1
    blob_repairer.check_index.assert_called_with(fast=False)

    assert blob_repairer.print_check_report.call_count == 1
