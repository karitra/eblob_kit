"""Test DiskControl structure."""
import pytest

from common import generate_key
from common import header_to_bytes

from eblob_kit import DiskControl
from eblob_kit import RecordFlags


@pytest.mark.parametrize('header', [
    DiskControl(key=generate_key(1),
                data_size=1,
                disk_size=2,
                flags=RecordFlags(0),
                position=0),
    DiskControl(key=generate_key(2),
                data_size=3,
                disk_size=4,
                flags=RecordFlags(RecordFlags.CORRUPTED),
                position=1),
    DiskControl(key=generate_key(3),
                data_size=4,
                disk_size=5,
                flags=RecordFlags(RecordFlags.EXTHDR),
                position=2),
    DiskControl(key=generate_key(4),
                data_size=5,
                disk_size=6,
                flags=RecordFlags(RecordFlags.CORRUPTED | RecordFlags.CHUNKED_CSUM),
                position=3),
])
def test_diskcontrol_from_bytes(header):
    """Dump header to byte sequence and construct it back."""
    assert header == DiskControl.from_raw(header_to_bytes(header))
