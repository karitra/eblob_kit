"""Tests common stuff."""
import struct
import sys

import eblob_kit


if sys.version_info < (3, 0):
    OPEN_TO_PATCH = '__builtin__.open'
else:
    OPEN_TO_PATCH = 'builtins.open'


def generate_key(start=0):
    """Generate valid key for testing."""
    return ''.join([chr((start + x) % 256) for x in xrange(eblob_kit.DiskControl.key_size)])


def make_header(key='', data_size=0, disk_size=0, flags=eblob_kit.RecordFlags(0), position=0):
    """Create DiskControl with default values.

    Parameters equals to eblob_kit.DiskControl constructor.

    With all defaults arguments construct an 'empty header', usually such a header should be considered 'non valid',
    used as a stub for tesing purposes.

    :rtype eblob_kit.DiskControl
    """
    return eblob_kit.DiskControl(key=key, data_size=data_size, disk_size=disk_size, flags=flags, position=position)


def header_to_bytes(header):
    """Construct bytes sequence DiskControl header representation.

    :param eblob_kit.DiskControl header: disk control header to pack into created buffer.

    :rtype: str
    """
    fmt = '<{}s4Q'.format(eblob_kit.DiskControl.key_size)
    return struct.pack(fmt, header.key, header.flags.flags, header.data_size, header.disk_size, header.position)


def make_blob_byte_squence(sizes=None, fill=0xf1):
    """Create a data blob.

    :param (List[int] | None) sizes: list of data chunks sizes
    :param int fill: fill the buffer with provided value.

    :rtype: bytearray
    """
    position = 0
    if sizes is None:
        sizes = []

    total_sizes = sum(size + eblob_kit.DiskControl.size for size in sizes)
    buff = bytearray([fill] * total_sizes)

    for key_sequence, size in enumerate(sizes):
        disk_size = eblob_kit.DiskControl.size + size
        header = make_header(key=generate_key(key_sequence), disk_size=disk_size, position=position)

        buff[position:position+eblob_kit.DiskControl.size] = header_to_bytes(header)

        position += disk_size

    return buff
