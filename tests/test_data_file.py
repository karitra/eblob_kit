"""DataFile tests."""
import pytest

import sys

# Used for file access emulation.
import StringIO

import common
import eblob_kit


TEST_OFFSETS_RANGE = 7


if sys.version_info < (3, 0):
    OPEN_TO_PATCH = '__builtin__.open'
else:
    OPEN_TO_PATCH = 'builtins.open'


def _make_buffer_with_valid_diskcontrol(disk_control_offset, disk_control):
    b = bytearray(disk_control_offset)
    b.extend(common.header_to_bytes(disk_control))
    return b


@pytest.fixture(params=[
    (1, 0, 0, 0, 0),
    (1, 0x01, 3, 4, 5),
    (3, 0xFFFF, 2**32, 2 ** 32, 2 ** 32),
])
def disk_control(request):
    """Generate some valid DiskControl instance.

    TODO(karapuz): add parameters with some marginal values.
    TODO(karapuz): use named tuple for test cases.

    """
    return eblob_kit.DiskControl(key=common.generate_key(request.param[0]),
                                 flags=eblob_kit.RecordFlags(request.param[1]),
                                 data_size=request.param[2],
                                 disk_size=request.param[3],
                                 position=request.param[4])


@pytest.mark.parametrize('disk_control_offset', xrange(TEST_OFFSETS_RANGE))
def test_read_disk_control_valid(mocker, disk_control, disk_control_offset):
    """Test read_disk_control along with eblob_kit.DataFile.read method."""
    dummy_buffer = _make_buffer_with_valid_diskcontrol(disk_control_offset,
                                                       disk_control)

    with mocker.patch(OPEN_TO_PATCH, return_value=StringIO.StringIO(dummy_buffer)),\
            mocker.patch('eblob_kit.DataFile.__len__', return_value=len(dummy_buffer)):

        data_file = eblob_kit.DataFile('some/path')
        dummy_disk_control = data_file.read_disk_control(disk_control_offset)

        assert dummy_disk_control == disk_control


@pytest.mark.xfail(raises=EOFError, strict=True)
@pytest.mark.parametrize('disk_control_offset', xrange(TEST_OFFSETS_RANGE))
def test_read_disk_control_with_exception(mocker, disk_control, disk_control_offset):
    """Test read_disk_control exceptions."""
    dummy_buffer = _make_buffer_with_valid_diskcontrol(disk_control_offset,
                                                       disk_control)
    # Truncate buffer to make it invalid
    dummy_buffer = dummy_buffer[:disk_control_offset + eblob_kit.DiskControl.size - 1]

    with mocker.patch(OPEN_TO_PATCH, return_value=StringIO.StringIO(dummy_buffer)),\
            mocker.patch('eblob_kit.DataFile.__len__', return_value=len(dummy_buffer)):
        eblob_kit.DataFile('some/path').read_disk_control(disk_control_offset)


@pytest.mark.parametrize('sizes', [
    [1, 2, 3],
    [1],
    [],
    [0],
    [0, 1],
    [0, 1, 1024, 512, 3]
])
def test_data_file_iter(mocker, sizes):
    """Check iterator over eblob_kit.DataFile records."""
    dummy_buffer = common.make_blob_byte_squence(sizes)

    with mocker.patch(OPEN_TO_PATCH, return_value=StringIO.StringIO(dummy_buffer)),\
            mocker.patch('eblob_kit.DataFile.__len__', return_value=len(dummy_buffer)):

        data_file = eblob_kit.DataFile('some/path')
        cnt = 0
        total_size = 0
        for disk_control in data_file:
            total_size += disk_control.disk_size
            cnt += 1

        assert cnt == len(sizes)
        assert len(dummy_buffer) == total_size
