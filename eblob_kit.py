#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Toolkit for working with eblob blobs."""

import errno
import glob
import hashlib
import json
import logging
import os
import re
import struct
import sys

from datetime import datetime
from datetime import timedelta

import click
import pyhash


def dump_digest(verbosity, results_digest):
    """Dump report to console as JSON.

    TODO(karapuz): tests

    :param int verbosity: verbosity level, dump JSON only if verbosity <= Verbosity.JSON
    :param Dict results_digest: report of command execution.

    """
    if verbosity > Verbosity.JSON:
        return

    try:
        json.dump({'files': results_digest}, sys.stdout)
    except Exception as e:
        logging.error('Failed to dump results to console: %s', e)


def dump_to_file(file_name, results):
    """Dump report to file as JSON.

    TODO(karapuz): tests

    :param str file_name: name of file to write report to.
    :param Dict results: dictionary to dump as JSON.

    """
    if not file_name:
        return

    try:
        directory_name = os.path.dirname(os.path.abspath(file_name))
        if not os.path.exists(directory_name):
            os.makedirs(directory_name)

        with open(file_name, 'wb') as out:
            json.dump({'files': results}, out)
    except Exception as e:
        logging.error('Failed to dump json report file %s: %s', file_name, e)


def is_destination_writable(src_path, dst_path, overwrite=False):
    """Check if 'dst_path' file writable.

    NOTE: always prohibit writing from src_path to dst_path if it is same file.

    """
    return not os.path.exists(dst_path) or (not os.path.samefile(src_path, dst_path) and overwrite)


class ReportType(object):
    """Command result report types.

    BASIC     - basic stat, e.g. counters, flags etc. Use for console digest report.
    EXTENDED  - BASIC, plus extended report on touched keys (if available). Use for
                report to file/database.

    """

    BASIC, EXTENDED = ('REPORT_TYPE_BASIC', 'REPORT_TYPE_EXTENDED')


JSON_OUTPUT = 'JSON_OUTPUT'

LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s: %(message)s (at %(filename)s:%(lineno)s)'


class Verbosity(object):
    """Levels of utility output verbosity.

    JSON - print json only digest report to stdout and extended to file if --json-out
           option is set. Note that logging is directed to stderr by default.

    If verbosity > JSON, then output via standard logger, no json format will be used.
    Logger could be configured to output via file. Any level > JSON is implicit for now,
    but 'enum' is open for appending of new verbosity levels.

    JSON is default verbosity level.

    """

    JSON = 0


class ChecksumTypes(object):
    SHA512 = 'sha512'
    CHUNKED = 'chunked'


class Record(object):
    """Represent record stored in blob."""
    def __init__(self, blob, index_idx=None, index_disk_control=None, data_disk_control=None):
        self._blob = blob
        self._index_idx = index_idx
        self._index_disk_control = index_disk_control
        self._data_disk_control = data_disk_control
        self._elliptics_header = None
        self._json_header = None

    @property
    def index_disk_control(self):
        """DiskControl from index file."""
        # index_disk_control isn't available if neither index_disk_control or index_idx was specified
        if self._index_disk_control is None and self._index_idx is not None:
            self._index_disk_control = self._blob.index[self._index_idx]

        return self._index_disk_control

    @property
    def data_disk_control(self):
        """DiskControl from data file."""
        if self._data_disk_control is None:
            self._data_disk_control = self._blob.data.read_disk_control(self.index_disk_control.position)

        return self._data_disk_control

    @property
    def elliptics_header(self):
        """Elliptics header from data file."""
        if self._elliptics_header is None:
            if self.data_disk_control.flags.exthdr:
                self._elliptics_header = self._blob.data.read_elliptics_header(self.data_disk_control.position)
            else:
                self._elliptics_header = EllipticsHeader('\0' * EllipticsHeader.size)

        return self._elliptics_header

    def verify_checksum(self):
        """Verify record's checksum.

        Returns:
            bool: whether checksum verification succeeded or not.
        """
        self._blob.verify_csum(self.data_disk_control)

    def mark_removed(self):
        """Mark record as removed."""
        logging.warning('Marking key: %s removed, in blob: "%s", with data-offset: %s, index-offset: %s',
                        self.data_disk_control.key.encode('hex'),
                        self._blob.data.path,
                        self.data_disk_control.position,
                        self._index_idx * DiskControl.size)

        removed_flags = struct.pack('<Q', RecordFlags.REMOVED)
        flags_offset = DiskControl.key_size

        logging.warning('Updating index: %s, offset: %s, flags: %s', self._blob.index.path,
                        (self._index_idx * DiskControl.size) + flags_offset, removed_flags.encode('hex'))

        self._blob.index.file.seek((self._index_idx * DiskControl.size) + flags_offset)
        self._blob.index.file.write(removed_flags)

        logging.warning('Updating data: %s, offset: %s, flags: %s', self._blob.data.path,
                        self.data_disk_control.position + flags_offset, removed_flags.encode('hex'))

        self._blob.data.file.seek(self.data_disk_control.position + flags_offset)
        self._blob.data.file.write(removed_flags)

        index_disk_control = self._blob.index[self._index_idx]
        data_disk_control = self._blob.data.read_disk_control(self.index_disk_control.position)

        assert index_disk_control == data_disk_control
        assert index_disk_control.flags.removed and data_disk_control.flags.removed

    def restore(self, checksum_type):
        logging.warning('Restoring key: %s, in blob: %s, with data-offset: %s, index-offset: %s,',
                        self.data_disk_control.key.encode('hex'),
                        self._blob.data.path,
                        self.data_disk_control.position,
                        self._index_idx * DiskControl.size)
        if not self.data_disk_control.flags.removed or not self.index_disk_control.flags.removed:
            logging.error('Key: %s is not marked removed in blob: %s or index: %s',
                          self.data_disk_control.key.encode('hex'),
                          self.data_disk_control.flags.removed, self.index_disk_control.flags.removed)
            return False

        record_flags = RecordFlags.EXTHDR

        if checksum_type == ChecksumTypes.CHUNKED:
            record_flags |= RecordFlags.CHUNKED_CSUM
        elif checksum_type == ChecksumTypes.SHA512:
            pass
        elif self._blob.verify_chunked_csum(self.data_disk_control):
            record_flags |= RecordFlags.CHUNKED_CSUM
        elif self._blob.verify_sha15_csum(self.data_disk_control):
            pass
        else:
            # TODO(shaitan): We could set RecordFlags.NOCSUM for such record but
            # it can be an error to assume that there is no checksum if we can't determine
            # the checksum type. This record can be corrupted or have new type of checksum which isn't supported yet by
            # eblob_kit.
            logging.error('Can not determine checksum type, key %s can not be restored',
                          self.data_disk_control.key.encode('hex'))
            return False

        restored_flags = struct.pack('<Q', record_flags)
        flags_offset = DiskControl.key_size

        logging.warning('Updating index: %s, offset: %s, flags: %s', self._blob.index.path,
                        (self._index_idx * DiskControl.size) + flags_offset, RecordFlags(record_flags))

        self._blob.index.file.seek((self._index_idx * DiskControl.size) + flags_offset)
        self._blob.index.file.write(restored_flags)

        logging.warning('Updating data: %s, offset: %s, flags: %s', self._blob.data.path,
                        self.data_disk_control.position + flags_offset, RecordFlags(record_flags))

        self._blob.data.file.seek(self.data_disk_control.position + flags_offset)
        self._blob.data.file.write(restored_flags)

        index_disk_control = self._blob.index[self._index_idx]
        data_disk_control = self._blob.data.read_disk_control(self.index_disk_control.position)

        assert index_disk_control == data_disk_control
        assert not index_disk_control.flags.removed and not data_disk_control.flags.removed
        assert index_disk_control.flags.exthdr and data_disk_control.flags.exthdr
        # assert index_disk_control.flags.chunked_csum and data_disk_control.flags.chunked_csum
        return True


class EllipticsHeader(object):
    """Elliptics extension header.

    TODO(karapuz): construction from byte stream (static method).
    TODO(karapuz): tests.

    """

    size = 48

    def __init__(self, data):
        assert len(data) == EllipticsHeader.size
        raw = struct.unpack('<4BI5Q', data)
        self.version = raw[0]
        self.__pad1 = raw[1:4]
        self.jhdr_size = raw[4]
        self.timestamp = datetime.fromtimestamp(raw[5]) + timedelta(microseconds=raw[6]/1000)
        self.user_flags = raw[7]
        self.__pad2 = raw[8:]

    def __str__(self):
        return 'timestamp: {}, user_flags: {}, version: {}'.format(self.timestamp, self.user_flags, self.version)


class RecordFlags(object):
    """Record flags."""

    REMOVED = 1 << 0
    NOCSUM = 1 << 1
    EXTHDR = 1 << 6
    UNCOMMITTED = 1 << 7
    CHUNKED_CSUM = 1 << 8
    CORRUPTED = 1 << 9

    _FLAGS = {
        REMOVED: 'removed',
        NOCSUM: 'nocsum',
        EXTHDR: 'exthdr',
        UNCOMMITTED: 'uncommitted',
        CHUNKED_CSUM: 'chunked_csum',
        CORRUPTED: 'corrupted',
    }

    def __init__(self, flags):
        """Initialize RecordFlags by value."""
        self.flags = flags

    def _set(self, flag, value):
        if value is True:
            self.flags |= flag
        elif value is False:
            self.flags &= ~flag

    removed = property(lambda self: self.flags & self.REMOVED,
                       lambda self, value: self._set(self.REMOVED, value),
                       lambda self: self._set(self.REMOVED, False))

    nocsum = property(lambda self: self.flags & self.NOCSUM,
                      lambda self, value: self._set(self.NOCSUM, value),
                      lambda self: self._set(self.NOCSUM, False))

    exthdr = property(lambda self: self.flags & self.EXTHDR,
                      lambda self, value: self._set(self.EXTHDR, value),
                      lambda self: self._set(self.EXTHDR, False))

    uncommitted = property(lambda self: self.flags & self.UNCOMMITTED,
                           lambda self, value: self._set(self.UNCOMMITTED, value),
                           lambda self: self._set(self.UNCOMMITTED, False))

    chunked_csum = property(lambda self: self.flags & self.CHUNKED_CSUM,
                            lambda self, value: self._set(self.CHUNKED_CSUM, value),
                            lambda self: self._set(self.CHUNKED_CSUM, False))

    corrupted = property(lambda self: self.flags & self.CORRUPTED,
                         lambda self, value: self._set(self.CORRUPTED, value),
                         lambda self: self._set(self.CORRUPTED, False))

    def __str__(self):
        """Convert flags to human-readable view."""
        flags = '|'.join(self._FLAGS[x] for x in self._FLAGS if self.flags & x)
        return '{:#6x} [{}]'.format(self.flags, flags)

    def __cmp__(self, other):
        """Compare self and other."""
        return self.flags != other.flags


class DiskControl(object):
    """Eblob record header.

    TODO(karapuz): properties docs.

    """

    size = 96
    key_size = 64

    def __init__(self, key, data_size, disk_size, flags, position):
        """Construct DiskControl with provided values."""
        self.key = key
        self.data_size = data_size
        self.disk_size = disk_size
        self.flags = flags
        self.position = position

    @staticmethod
    def from_raw(data):
        """Initialize from raw @data."""

        assert len(data) == DiskControl.size

        key = data[:DiskControl.key_size]
        raw = struct.unpack('<4Q', data[DiskControl.key_size:])

        flags = RecordFlags(raw[0])
        data_size = raw[1]
        disk_size = raw[2]
        position = raw[3]

        return DiskControl(key=key, data_size=data_size, disk_size=disk_size, flags=flags, position=position)

    @property
    def hex_key(self):
        """Stringify key as hex sequence."""
        return self.key.encode('hex')

    @property
    def raw_data(self):
        """Convert DiskControl to raw format."""
        raw = struct.pack('<4Q', self.flags.flags, self.data_size, self.disk_size, self.position)
        return self.key + raw

    def to_dict(self):
        return {
            'key': self.key,
            'position': self.position,
            'data_size': self.data_size,
            'disk_size': self.disk_size,
            'flags': self.flags.flags,
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    def __nonzero__(self):
        """Return true if self is valid."""
        return self.data_size != 0 and self.disk_size != 0

    def __str__(self):
        """Make human-readable string."""
        return '{}: position: {:12} data_size: {} ({}) disk_size: {} ({}) flags: {}'.format(
            self.hex_key, self.position,
            self.data_size, sizeof_fmt(self.data_size),
            self.disk_size, sizeof_fmt(self.disk_size),
            self.flags)

    def __cmp__(self, other):
        """Compare self with other."""
        return cmp((self.key, self.flags, self.data_size, self.disk_size, self.position),
                   (other.key, other.flags, other.data_size, other.disk_size, other.position))


class IndexFile(object):
    """Abstraction to index file."""

    def __init__(self, path, mode='rb'):
        """Initialize IndexFile object again @path."""
        if path.endswith('.index.sorted'):
            self.sorted = True
        elif path.endswith('.index'):
            self.sorted = False
        else:
            raise RuntimeError('{} is not index'.format(path))
        self._file = open(path, mode)

    @staticmethod
    def create(path):
        """Create IndexFile for @path.

        NOTE: underlying file is truncuated if exists.
        """
        return IndexFile(path=path, mode='wb')

    @property
    def path(self):
        """Return path to the index file."""
        return self._file.name

    @property
    def file(self):
        """Return file."""
        return self._file

    def append(self, header):
        """Append header to index."""
        self._file.write(header.raw_data)

    def size(self):
        """Size of the file."""
        return os.fstat(self._file.fileno()).st_size

    def __getitem__(self, idx):
        assert (idx + 1) * DiskControl.size <= self.size()
        self._file.seek(idx * DiskControl.size)
        return DiskControl.from_raw(self._file.read(DiskControl.size))

    def __len__(self):
        """Return number of headers in index file."""
        return self.size() / DiskControl.size

    def __iter__(self):
        """Iterate over headers in the index."""
        self._file.seek(0)
        index_content = self._file.read()
        for offset in xrange(0, len(index_content), DiskControl.size):
            data = index_content[offset: offset + DiskControl.size]
            if len(data) != DiskControl.size:
                raise EOFError('Failed to read header at offset {} of {} ({})'
                               .format(offset, self.path, self.size()))
            yield DiskControl.from_raw(data)


class DataFile(object):
    """Abstraction to data file."""

    def __init__(self, path, mode='rb'):
        """Initialize DataFile object again @path."""
        self.sorted = os.path.exists(path + '.data_is_sorted') and \
            os.path.exists(path + '.index.sorted')
        self._file = open(path, mode)

    @property
    def path(self):
        """Return path to the data file."""
        return self._file.name

    @property
    def file(self):
        """Return file."""
        return self._file

    def read_disk_control(self, position):
        """Read DiskControl at @offset."""
        return DiskControl.from_raw(self.read(position, DiskControl.size))

    def read_elliptics_header(self, position):
        """Read header at position."""
        return EllipticsHeader(self.read(position + DiskControl.size, EllipticsHeader.size))

    def read(self, offset, size):
        """Read @size bytes from @offset."""
        if offset > len(self):
            raise EOFError('Illegal seek: offset ({}) is out of file ({})'
                           .format(offset, len(self)))
        if offset + size > len(self):
            raise EOFError('Illegal seek: offset + size ({}) is out of file ({})'
                           .format(offset + size, len(self)))

        self._file.seek(offset)
        return self._file.read(size)

    def __iter__(self):
        """Iterate over headers in the blob."""
        self._file.seek(0)
        while True:
            offset = self._file.tell()
            data = self._file.read(DiskControl.size)
            if len(data) == 0:
                break
            if len(data) != DiskControl.size:
                raise EOFError('Failed to read header at offset: {}'.format(offset))
            header = DiskControl.from_raw(data)
            yield header
            self._file.seek(offset + header.disk_size)

    def __len__(self):
        """Return size of data file."""
        return os.fstat(self._file.fileno()).st_size


class Blob(object):
    """Abstraction to blob consisted from index and data files."""

    def __init__(self, path, mode='rb'):
        """Initialize Blob object against @path."""
        if os.path.exists(path + '.index.sorted'):
            self._index_file = IndexFile(path + '.index.sorted', mode)
        elif os.path.exists(path + '.index'):
            self._index_file = IndexFile(path + '.index', mode)
        else:
            raise IOError('Could not find index for {}'.format(path))

        self._data_file = DataFile(path, mode)

    @staticmethod
    def create(path, mark_index_sorted=False):
        """Create new Blob at @path.

        NOTE: underlying files are truncuated if they are exist.
        """
        index_suffix = '.index.sorted' if mark_index_sorted else '.index'

        create_mode = 'wb'
        # Index is checked for existance on Blob creation, so we should create it
        # beforehand, but data file would be created within Blob constructor.
        open(path + index_suffix, create_mode).close()

        return Blob(path=path, mode=create_mode)

    @property
    def index(self):
        """Return index file."""
        return self._index_file

    @property
    def data(self):
        """Return data file."""
        return self._data_file

    def _murmur_chunk(self, chunk):
        """Apply murmurhash to chunk and return raw result."""
        chunk_size = 4096
        result = 0
        hasher = pyhash.murmur2_x64_64a()
        while chunk:
            result = hasher(chunk[:chunk_size], seed=result)
            chunk = chunk[chunk_size:]
        return struct.pack('<Q', result)

    def murmur_record_data(self, header, chunk_size):
        """Apply murmurhash to record's data pointed by @header."""
        self.data.file.seek(header.position + DiskControl.size)

        length = header.data_size
        while length:
            chunk_size = min(length, chunk_size)
            yield self._murmur_chunk(self.data.file.read(chunk_size))
            length -= chunk_size

    def verify_chunked_csum(self, header):
        """Verify chunked checksum of the record pointer by @header."""
        footer_size = 8

        chunk_size = 1 << 20
        chunks_count = ((header.disk_size - DiskControl.size - footer_size - 1) / (chunk_size + footer_size)) + 1
        footer_offset = header.position + header.disk_size - (chunks_count + 1) * footer_size

        calculated_csum = ''.join(self.murmur_record_data(header, chunk_size))

        self.data.file.seek(footer_offset)
        stored_csum = self.data.file.read(len(calculated_csum))
        if calculated_csum != stored_csum:
            logging.error('Invalid csum, stored (%s) != calculated (%s): %s',
                          stored_csum.encode('hex'),
                          calculated_csum.encode('hex'),
                          header)
            return False

        return True

    def verify_sha15_csum(self, header):
        """Verify sha512 checksum of the record pointer by @header."""
        self.data.file.seek(header.position + DiskControl.size)

        length = header.data_size
        chunk = 32768
        hasher = hashlib.sha512()
        while length:
            chunk = min(length, chunk)
            hasher.update(self.data.file.read(chunk))
            length -= chunk

        calculated_csum = hasher.digest()

        footer_size = 64 + 8

        self.data.file.seek(header.position + header.disk_size - footer_size)
        stored_csum = self.data.file.read(footer_size)[:64]

        if calculated_csum != stored_csum:
            logging.error('Invalid csum, stored (%s) != calculated (%s): %s',
                          stored_csum.encode('hex'),
                          calculated_csum.encode('hex'),
                          header)
            return False

        return True

    def verify_csum(self, header):
        """Verify checksum of the record pointed by @header."""
        if header.flags.nocsum:
            return True

        if header.flags.chunked_csum:
            return self.verify_chunked_csum(header)
        else:
            return self.verify_sha15_csum(header)


def sizeof_fmt(num, suffix='B'):
    """Convert @num into human-readable string."""
    for unit in ('', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi'):
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, 'Yi', suffix)


def range_fmt(start, end):
    """Format @start, @end range as [{start}, {end}] ({size})."""
    return '[{}, {}) ({})'.format(start, end, sizeof_fmt(end - start))


def header_range_fmt(header):
    """Format header as [{start}, {end}] ({size})."""
    return range_fmt(header.position, header.position + header.disk_size)


def get_checksum_size(header):
    """Return checksum for the header."""
    if header.flags.nocsum:
        return 0

    if header.flags.chunked_csum:
        footer_size = 8
        chunk_size = 1 << 20  # 1 MiB
        return (((header.data_size - 1) / chunk_size) + 2) * footer_size
    else:
        return 64


def copy_record(src, dst, header):
    """Copy record from @src to @dst specified by @header."""
    new_header = header.key + struct.pack('<4Q', header.flags.flags, header.data_size,
                                          header.disk_size, dst.data.file.tell())
    dst.index.file.write(new_header)
    dst.data.file.write(new_header)

    chunk_size = 409600
    length = header.disk_size - DiskControl.size
    src.data.file.seek(header.position + DiskControl.size)
    while length > 0:
        chunk_size = min(chunk_size, length)
        dst.data.file.write(src.data.file.read(chunk_size))
        length -= chunk_size


def files(path):
    """Iterate over files by pattern."""
    blob_re = re.compile(path + '-0.[0-9]+$')
    return (filename for filename in glob.iglob(path + '-0.*')
            if blob_re.match(filename))


def read_keys(keys_path, short):
    with open(keys_path, 'r') as keys_file:
        # 28 is 12 bytes + '...' + 12 bytes + '\n' -  'f1ddefc58a5d...89b550cc034c\n'
        # 129 is 128 bytes of key + '\n'
        return [line[:-1] for line in keys_file if len(line) == (28 if short else 129)]


class BlobRepairerStat(object):
    """Blob repair process stat.

    TODO(karapuz): tests
    """

    def __init__(self):
        """Construct BlobRepairerStat with zeroed stat."""
        self.index_order_error = False
        self.invalid_index_size = False

        self.index_malformed_headers = 0
        self.index_malformed_headers_keys = set()

        self.corrupted_data_headers = 0
        self.corrupted_data_headers_keys = set()
        self.corrupted_data_headers_size = 0

        self.index_removed_headers = 0
        self.index_removed_headers_keys = set()
        self.index_removed_headers_size = 0

        self.index_uncommitted_headers = 0
        self.index_uncommitted_headers_keys = set()
        self.index_uncommitted_headers_size = 0

        self.data_recoverable_headers = []
        self.mismatched_headers = []
        self.holes = 0
        self.holes_size = 0

    @property
    def as_dict(self):
        """Compose stat report as dict.

        :rtype: Dict[str, (numeric | List)]
        """
        result = self.as_digest_dict
        result.update({
            'index_malformed_headers_keys':
                list(self.index_malformed_headers_keys),
            'corrupted_data_headers_keys':
                list(self.corrupted_data_headers_keys),
            'index_removed_headers_keys':
                list(self.index_removed_headers_keys),
            'index_uncommitted_headers_keys':
                list(self.index_uncommitted_headers_keys),
            'data_recoverable_headers_keys': [
                k.hex_key for k in self.data_recoverable_headers],

            # TODO(karapuz): put here hashes from both index and data.
            'mismatched_headers': [
                d.hex_key for _, d in self.mismatched_headers],
        })

        return result

    @property
    def as_digest_dict(self):
        """Compose repair report digest."""
        return {
            'index_order_error': self.index_order_error,
            'invalid_index_size': self.invalid_index_size,
            'index_malformed_headers': self.index_malformed_headers,
            'corrupted_data_headers': self.corrupted_data_headers,
            'index_removed_headers': self.index_removed_headers,
            'index_uncommitted_headers': self.index_uncommitted_headers,
        }


class BlobRepairer(object):
    """Check and repair blob."""

    def __init__(self, path):
        """Initialize BlobRepairer for blob at @path."""
        self._blob = Blob(path)
        self._valid = True

        self._index_headers = []

        self._stat = BlobRepairerStat()

    @property
    def stat(self):
        """Return BlobRepairerStat object."""
        return self._stat

    @property
    def valid(self):
        """Return current repairer status.

        True, if it wasn't any inconsistency found while processing blob.
        """
        return self._valid

    def check_header(self, header):
        """Check header correctness."""
        if header.disk_size == 0:
            logging.error('malformed header has empty disk_size: %s', header)
            return False

        if header.position + header.disk_size > len(self._blob.data):
            logging.error('malformed header has position (%d) + disk_size (%d) '
                          'is out of %s (%d): %s',
                          header.position, header.disk_size,
                          self._blob.data.path, len(self._blob.data), header)
            return False

        if not header.flags.uncommitted and not header.flags.removed:
            if header.data_size == 0:
                logging.error('malformed header has empty data_size but it is committed: %s', header)
                return False

            extension_header_size = EllipticsHeader.size if header.flags.exthdr else 0
            checksum_size = get_checksum_size(header)

            if header.data_size + extension_header_size + checksum_size > header.disk_size:
                logging.error('malformed header has data_size (%d) + extension_header_size (%d) + '
                              'checksum_size (%d) > disk_size (%d): %s',
                              header.data_size, extension_header_size, checksum_size,
                              header.disk_size, header)
                return False

        return True

    def check_hole(self, position, end):
        """Check headers in data in area [@position, @end)."""
        logging.error('I have found hole in data %s which is not '
                      'covered by valid headers from index',
                      range_fmt(position, end))

        while position < end:
            try:
                data_header = self._blob.data.read_disk_control(position)
            except EOFError as exc:
                logging.error('Failed to read header from data: %s', exc)
                break
            if data_header.position != position:
                logging.error('Header in data at offset %d has invalid offset %d. '
                              'I will correct position of the record and '
                              'will try to use corrected version of the header',
                              position, data_header.position)
                data_header.position = position

            if not self.check_header(data_header):
                logging.error('I have found record which is missed in index and '
                              'has invalid header in data at %d. I can not recover it, '
                              'so I will skip it and everything in %s from data: %s',
                              position, range_fmt(position, end), data_header)
                break
            elif data_header.position + data_header.disk_size > end:
                logging.error('Header (%s) is beyond the hole %s: %s',
                              header_range_fmt(data_header),
                              range_fmt(position, end),
                              data_header)
                break
            else:
                logging.info('I have found valid header at position %d in data and '
                             'will add it to headers list', position)
                if not data_header.flags.removed and not data_header.flags.uncommitted:
                    self._stat.data_recoverable_headers.append(data_header)
                position += data_header.disk_size

        if position != end:
            self._stat.holes += 1
            self._stat.holes_size += end - position

    def resolve_mispositioned_record(self, header_idx, position, valid_headers):
        """Try to resolve mispositioned record failure.

        Return whether header at @header_idx should be skipped.
        """
        header = self._index_headers[header_idx]

        assert header_idx > 0, 'Mispositioned record failure can not occur with first header'
        previous_header = self._index_headers[header_idx - 1]
        assert position == previous_header.position + previous_header.disk_size,\
            'Previous header should be placed exactly before position'
        assert previous_header.position <= header.position, 'Headers should be sorted by position'

        data_header = self._blob.data.read_disk_control(header.position)

        if header != data_header:
            logging.error('Mispositioned record does not match header from data. Skip it: %s',
                          header)
            return True
        elif valid_headers and valid_headers[-1] == previous_header:
            logging.error('Mispositioned record does match header from data, so I remove '
                          'previous conflicting record which was correct. '
                          'current: %s, previous: %s', header, previous_header)
            del valid_headers[-1]
        elif self._stat.mismatched_headers and self._stat.mismatched_headers[-1][0] == previous_header:
            logging.error('Mispositioned record does match header from data, so I remove '
                          'previous conflicting record which was mismatched. '
                          'current: %s, previous: %s', header, previous_header)
            del self._stat.mismatched_headers[-1]

        return False

    def resolve_mismatch(self, index_header, data_header, valid_headers):
        """Try to resolve mismatch if it is detected."""
        self._stat.mismatched_headers.append((index_header, data_header))
        self._valid = False

        logging.error('Headers mismatches: data_header: %s, index_header: %s',
                      data_header, index_header)

    def check_index(self, fast):
        """Check that index file is correct."""
        prev_key = None
        try:
            logging.info('Checking index: %s', self._blob.index.path)

            for header in self._blob.index:
                if fast and not self._valid:
                    # return if it is fast-check and there was an error
                    return
                if self.check_header(header):
                    self._index_headers.append(header)
                    if prev_key and self._blob.index.sorted:
                        if prev_key > header.key:
                            self._valid = False
                            self._blob.index.sorted = False
                            self._stat.index_order_error = True
                    prev_key = header.key
                else:
                    self._stat.index_malformed_headers_keys.add(header.hex_key)
                    self._stat.index_malformed_headers += 1

                    self._valid = False
        except EOFError as exc:
            logging.error('Failed to read header path %s, error %s. Skip other headers in index',
                          self._blob.index.path,
                          exc)

            self._stat.invalid_index_size = True
            self._valid = False

        if fast and not self._valid:
            return

        if self._stat.index_order_error:
            logging.error('%s is supposed to be sorted, but it has disordered headers', self._blob.index.path)

        if self._stat.index_malformed_headers or self._stat.invalid_index_size:
            logging.error('%s has %s malformed and %s valid headers',
                          self._blob.index.path,
                          self._stat.index_malformed_headers,
                          len(self._index_headers))
        else:
            logging.info('All %d headers in %s are valid',
                         len(self._index_headers),
                         self._blob.index.path)

        if not fast:
            self._index_headers = sorted(self._index_headers, key=lambda h: h.position)

    def print_check_report(self):
        """Print report after check."""
        if self._valid:
            report = '{} is valid and has:'.format(self._blob.data.path)
            report += '\n\t{} valid records'.format(len(self._index_headers))
            report += '\n\t{} removed records ({})'.format(
                self._stat.index_removed_headers, sizeof_fmt(self._stat.index_removed_headers_size))
            report += '\n\t{} uncommitted records ({})'.format(
                self._stat.index_uncommitted_headers, sizeof_fmt(self._stat.index_uncommitted_headers_size))
            logging.info(report)
            return

        report = '{} has:'.format(self._blob.data.path)
        report += '\n\t{} headers ({}) from index are valid'.format(
            len(self._index_headers), sizeof_fmt(sum(h.disk_size for h in self._index_headers)))
        if self._stat.index_removed_headers:
            report += '\n\t{} headers ({}) from index are valid and marked as removed'.format(
                self._stat.index_removed_headers, sizeof_fmt(self._stat.index_removed_headers_size))
        if self._stat.index_uncommitted_headers:
            report += '\n\t{} headers ({}) from index are valid and marked as uncommitted'.format(
                self._stat.index_uncommitted_headers, sizeof_fmt(self._stat.index_uncommitted_headers_size))

        if self._stat.mismatched_headers:
            report += '\n\t{} headers which are different in the blob and in the index'.format(
                len(self._stat.mismatched_headers))

        if self._stat.data_recoverable_headers:
            report += '\n\t{} headers ({}) can be recovered from data'.format(
                len(self._stat.data_recoverable_headers),
                sizeof_fmt(sum(h.disk_size for h in self._stat.data_recoverable_headers)))
        if self._stat.holes:
            report += '\n\t{} holes ({}) in blob which are not marked'.format(
                self._stat.holes, sizeof_fmt(self._stat.holes_size))
        if self._stat.index_order_error:
            report += '\n\t{} is supposed to be sorted but it has disordered header'.format(
                self._blob.index.path)
        if self._stat.corrupted_data_headers:
            report += '\n\t{} headers ({}) has corrupted data'.format(
                self._stat.corrupted_data_headers, sizeof_fmt(self._stat.corrupted_data_headers_size))

        logging.error(report)

        if (not self._index_headers and
                not self._stat.index_removed_headers and
                not self._stat.index_uncommitted_headers):
            logging.error('%s does not match %s', self._blob.index.path, self._blob.data.path)

    def check(self, verify_csum, fast):
        """Check that both index and data files are correct."""
        self.check_index(fast=fast)

        if fast:
            return self._valid

        valid_headers = []

        position = 0
        logging.info('Checking: %s', self._blob.data.path)

        for header_idx, index_header in enumerate(self._index_headers):
            if position > index_header.position:
                self.resolve_mispositioned_record(header_idx, position, valid_headers)

            if position < index_header.position:
                self._valid = False
                self.check_hole(position, index_header.position)

            data_header = self._blob.data.read_disk_control(index_header.position)
            if index_header == data_header:
                if index_header.flags.removed:
                    self._stat.index_removed_headers += 1
                    self._stat.index_removed_headers_keys.add(data_header.hex_key)
                    self._stat.index_removed_headers_size += index_header.disk_size
                elif index_header.flags.uncommitted:
                    self._stat.index_uncommitted_headers += 1
                    self._stat.index_uncommitted_headers_keys.add(data_header.hex_key)
                    self._stat.index_uncommitted_headers_size += index_header.disk_size
                else:
                    if verify_csum:
                        if not self._blob.verify_csum(index_header):
                            self._stat.corrupted_data_headers += 1
                            self._stat.corrupted_data_headers_keys.add(data_header.hex_key)
                            self._stat.corrupted_data_headers_size += index_header.disk_size
                            self._valid = False
                        else:
                            valid_headers.append(index_header)
                    else:
                        valid_headers.append(index_header)
            else:
                self.resolve_mismatch(index_header, data_header, valid_headers)

            position = index_header.position + index_header.disk_size

        if position < len(self._blob.data):
            self._valid = False
            self.check_hole(position, len(self._blob.data))

        self._index_headers = valid_headers

        return self._valid

    @staticmethod
    def recover_index(data, destination, overwrite=False):
        """Recover index from data."""
        basename = os.path.basename(data.path)
        index_path = os.path.join(destination, basename + '.index')

        if not is_destination_writable(data.path + '.index', index_path, overwrite):
            raise RuntimeError("can't recover to already existing index file: {}".format(index_path))

        index = IndexFile.create(index_path)

        logging.info('Recovering index %s -> %s', data.path, index_path)

        for header in data:
            if header:
                index.append(header)
                continue

            offset = data.file.tell() - DiskControl.size
            logging.error('I have found broken header at offset %s: %s', offset, header)
            logging.error('This record can not be skipped, so I break the recovering. '
                          'You can use %s as an index for %s but it does not include '
                          'records after %s offset',
                          index.path,
                          data.path,
                          offset)
            break

    def recover_blob(self, destination, overwrite=False):
        """Recover blob from data."""
        basename = os.path.basename(self._blob.data.path)
        blob_path = os.path.join(destination, basename)

        if not is_destination_writable(self._blob.data.path,  blob_path, overwrite):
            raise RuntimeError("can't recover to already existing blob file: {}".format(blob_path))

        blob = Blob.create(path=blob_path)

        copied_records = 0
        removed_records = 0
        skipped_records = 0

        logging.info('Recovering blob %s -> %s', self._blob.data.path, blob_path)

        for header in self._blob.data:
            if not header:
                skipped_records += 1
                logging.error('I have faced with broken record which I have to skip.')
            elif header.flags.removed:
                removed_records += 1
            else:
                copy_record(self._blob, blob, header)
                copied_records += 1

        logging.info('I have copied %s records, skipped %s and removed %s records',
                     copied_records,
                     skipped_records,
                     removed_records)

    def copy_valid_records(self, destination, overwrite=False):
        """Recover blob by copying only valid records from blob."""
        basename = os.path.basename(self._blob.data.path)
        blob_path = os.path.join(destination, basename)

        if not is_destination_writable(self._blob.data.path,  blob_path, overwrite):
            raise RuntimeError("can't copy valid records to already existing blob file: {}".format(blob_path))

        blob = Blob.create(blob_path)

        copied_records = 0
        copied_size = 0

        self._index_headers += self._stat.data_recoverable_headers
        logging.info('Recovering blob %s -> %s', self._blob.data.path, blob_path)

        for header in self._index_headers:
            copy_record(self._blob, blob, header)
            copied_records += 1
            copied_size += header.disk_size

        logging.info('I have copied %s (%s) records %s -> %s ',
                     copied_records,
                     sizeof_fmt(copied_size),
                     self._blob.data.path,
                     blob_path)

    def fix(self, destination, noprompt, overwrite=False):
        """Check blob's data & index and try to fix them if they are broken.

        TODO(karapuz): remove all interactive user interaction.

        """
        self.check(verify_csum=True, fast=False)
        self.print_check_report()

        if self._valid:
            return

        if (not self._index_headers and
                not self._stat.index_removed_headers and
                not self._stat.index_uncommitted_headers):

            if noprompt:
                self.recover_blob(destination, overwrite=overwrite)
            elif click.confirm('There is no valid header in {}. '
                               'Should I try to recover index from {}?'
                               .format(self._blob.index.path, self._blob.data.path),
                               default=True):
                self.recover_index(self._blob.data, destination, overwrite=overwrite)
            elif click.confirm('Should I try to recover both index and data from {}?'
                               .format(self._blob.data.path),
                               default=True):
                self.recover_blob(destination, overwrite=overwrite)
        else:
            if not self._index_headers:
                logging.error('Nothing can be recovered from %s, so it should be removed', self._blob.data.path)
                filname = '{}.should_be_removed'.format(
                    os.path.join(destination, os.path.basename(self._blob.data.path)))
                with open(filname, 'wb'):
                    pass
            elif noprompt or click.confirm('Should I repair {}?'.format(self._blob.data.path),
                                           default=True):
                self.copy_valid_records(destination, overwrite=overwrite)


def find_duplicates(blobs):
    """Find duplicates and return information about them."""
    unique_keys = {}
    duplicates = {}
    for blob in blobs:
        index_file = None
        if os.path.exists(blob + '.index.sorted'):
            index_file = IndexFile(blob + '.index.sorted')
        elif os.path.exists(blob + '.index'):
            index_file = IndexFile(blob + '.index')
        else:
            raise IOError('Could not find index for {}'.format(blob))

        stat_chunk = 1 << 15
        with click.progressbar(length=len(index_file),
                               label='Iterating: {}'.format(index_file.path)) as pbar:
            for header_idx, header in enumerate(index_file):
                if (header_idx + 1) % stat_chunk == 0:
                    pbar.update(stat_chunk)

                if header.flags.removed:
                    continue

                info = blob, header_idx

                if header.key in duplicates:
                    duplicates[header.key] += [info]
                elif header.key in unique_keys:
                    duplicates[header.key] = [unique_keys[header.key], info]
                    del unique_keys[header.key]
                else:
                    unique_keys[header.key] = info

            pbar.update(stat_chunk)

    # for key in duplicates:
    #     logging.error('Found key: %s in blobs: %s', key.encode('hex'), set([path for path, _ in duplicates[key]]))

    report = 'I have found {} keys which have {} duplicates'.format(
        len(duplicates),
        sum(len(value) - 1 for value in duplicates.itervalues())
    )

    if duplicates:
        logging.error(report)
    else:
        logging.info(report)

    return duplicates


def remove_duplicates(blobs):
    """Find and remove keys' duplicates."""
    duplicates = sorted((sorted(value), key) for key, value in find_duplicates(blobs).iteritems())

    stat_chunk = 1 << 10
    with click.progressbar(length=len(duplicates), label='Removing duplicates') as pbar:
        blobs_files = {}
        removed_duplicates = 0
        for idx, (key_duplicates, key) in enumerate(duplicates):
            if (idx + 1) % stat_chunk == 0:
                pbar.update(stat_chunk)

            valid_duplicates = []
            invalid_duplicates = []
            for blob_path, header_idx in key_duplicates:
                if blob_path not in blobs_files:
                    blobs_files[blob_path] = Blob(blob_path, mode='r+b')

                record = Record(blob=blobs_files[blob_path], index_idx=header_idx)

                if record.data_disk_control != record.index_disk_control:
                    # skip records with headers mismatch
                    logging.error('Key: %s has headers\' mismatch, skip it. Try to fix blob: %s',
                                  key.encode('hex'), blob_path)
                    continue

                assert record.index_disk_control.key == key
                assert not record.index_disk_control.flags.removed

                if record.index_disk_control.flags.uncommitted:
                    valid_duplicates.append(record)
                    continue

                if not record.verify_checksum():
                    logging.error('Key: %s has failed checksum verification, it will be removed', key.encode('hex'))
                    invalid_duplicates.append(record)
                    continue

                valid_duplicates.append(record)

            records_to_remove = invalid_duplicates

            if not valid_duplicates:
                logging.error('Key: %s has no valid duplicates, so all (%s) of them will be removed',
                              key.encode('hex'),
                              len(invalid_duplicates))
            else:
                valid_duplicates.sort(
                    key=lambda r: (r.elliptics_header.timestamp, not r.data_disk_control.flags.uncommitted),
                    reverse=True)
                logging.error('Key: %s has %s valid duplicates and %s invalid duplicates, '
                              'all of them except one will be removed',
                              key.encode('hex'), len(valid_duplicates), len(invalid_duplicates))
                records_to_remove += valid_duplicates[1:]

            if records_to_remove:
                logging.error('I am about to remove %s duplicates: %s', len(records_to_remove), records_to_remove)
                for record in records_to_remove:
                    record.mark_removed()
                removed_duplicates += len(records_to_remove)

        logging.error('Duplicates removed: %s', removed_duplicates)

        pbar.update(stat_chunk)


def restore_record(blob_path, index_idx, checksum_type):
    record = Record(blob=Blob(blob_path, mode='r+b'), index_idx=index_idx)
    return record.restore(checksum_type)


def restore_keys(blobs, keys, short, checksum_type):
    # dict to store all available records for each key
    keys = {key: [] for key in keys}

    if not keys:
        logging.warning('No key should be restored')
        return True

    for blob_path in blobs:
        blob_idx = int(blob_path[blob_path.find('.') + 1:])
        if os.path.exists(blob_path + '.index.sorted'):
            index_file = IndexFile(blob_path + '.index.sorted')
        elif os.path.exists(blob_path + '.index'):
            index_file = IndexFile(blob_path + '.index')
        else:
            raise IOError('Could not find index for {}'.format(blob_path))

        stat_chunk = 1 << 10
        with click.progressbar(length=len(index_file), label='Iterating: {}'.format(index_file.path)) as pbar:
            for header_idx, header in enumerate(index_file, start=1):
                if header_idx % stat_chunk == 0:
                    pbar.update(stat_chunk)

                key = header.key.encode('hex')
                if short:
                    key = '{}...{}'.format(key[:12], key[-12:])

                if key not in keys:
                    continue

                if not header.flags.removed:
                    logging.warning('Found alive record for key: %s, in blob: %s', header, blob_path)
                    del keys[key]
                    continue

                keys[key].append(((blob_idx, header.position), (blob_path, header_idx - 1)))
            pbar.update(stat_chunk)

    if not keys:
        logging.warning('No key should be restored')
        return True

    keys_to_restore = []
    for key, records in keys.iteritems():
        if len(records) == 0:
            logging.error('I have not found key: %s, so it can not be restored', key)
            continue

        (_, position), (blob_path, index_idx) = records[0]
        if len(records) > 1:
            (_, position), (blob_path, index_idx) = sorted(records)[-1]

        keys_to_restore.append((blob_path, position, index_idx))
    keys_to_restore.sort()

    result = True
    with click.progressbar(length=len(keys), label='Restoring') as pbar:
        for key_idx, (blob_path, _, index_idx) in enumerate(keys_to_restore, start=1):
            if key_idx % stat_chunk == 0:
                pbar.update(stat_chunk)

            result &= restore_record(blob_path, index_idx, checksum_type)
        pbar.update(stat_chunk)
    return result


@click.group()
@click.version_option()
@click.pass_context
@click.option('-l', '--log-file', default=None, help='File for logs.')
@click.option('-j', '--json-file', default=None, help='File for JSON report.')
@click.option('-v', '--verbose',
              count=True,
              help='Specify verbosity level, accumulate to increase verbosity level')
def cli(ctx, log_file, json_file, verbose):
    """eblob_kit is the tool for diagnosing, recovering and listing blobs.

    \b
    Verbosity levels currently supported:
      - no verbosity: ouput resulting json to stdout on task completion.
      - set once: print log to stdout, possible along with log-file, that could be set with -l option.
    """
    level = logging.INFO if verbose else logging.ERROR

    if log_file is None:
        # NOTE: defaults to stderr.
        logging.basicConfig(format=LOG_FORMAT, level=level)
    else:
        dir_name = os.path.dirname(os.path.abspath(log_file))
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)

        root_logger = logging.getLogger()

        log_formatter = logging.Formatter(fmt=LOG_FORMAT)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(log_formatter)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)

        root_logger.setLevel(level)

        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)

    if json_file:
        ctx.obj[JSON_OUTPUT] = json_file

    ctx.obj['VERBOSITY'] = verbose


@cli.command(name='list_index')
@click.argument('path')
def list_index_command(path):
    """List index file specified by @PATH."""
    assert os.path.exists(path), 'Failed to listing index: {}: file does not exist'.format(path)
    for header in IndexFile(path):
        print header


@cli.command(name='list_data')
@click.argument('path')
def list_data_command(path):
    """List data file specified by @PATH."""
    assert os.path.exists(path), 'Failed to listing data: {}: failed does not exist'.format(path)
    for header in DataFile(path):
        print header


@cli.command(name='list')
@click.argument('path')
@click.pass_context
def list_command(ctx, path):
    """List data or index file specified by @PATH."""
    if path.endswith('.index') or path.endswith('.index.sorted'):
        ctx.invoke(list_index_command, path=path)
    else:
        ctx.invoke(list_data_command, path=path)


@cli.command(name='check_blob')
@click.argument('path')
@click.option('-V', '--verify-csum', is_flag=True, default=False, help='V for verify checksum')
@click.option('-f', '--fast', is_flag=True, default=False, help='Quickly check blob')
@click.pass_context
def check_blob_command(ctx, path, verify_csum, fast):
    """Check that blob (its data and index) is correct."""
    try:
        repairer = BlobRepairer(path)
        result = repairer.check(verify_csum=verify_csum, fast=fast)
        if not result or not fast:
            repairer.print_check_report()
        if 'result' in ctx.obj:
            ctx.obj['result'] &= result
        else:
            ctx.exit(not result)
    except IOError as exc:
        logging.error('I have failed to open %s: %s', path, exc)


@cli.command(name='check')
@click.argument('path')
@click.option('-V', '--verify-csum', is_flag=True, default=False, help='V for verify checksum')
@click.option('-f', '--fast', is_flag=True, default=False, help='Quickly check blob')
@click.pass_context
def check_command(ctx, path, verify_csum, fast):
    """Check that all blobs (datas and indexes) are correct."""
    ctx.obj['result'] = True
    for blob_path in files(path):
        ctx.invoke(check_blob_command, path=blob_path, verify_csum=verify_csum, fast=fast)
    ctx.exit(not ctx.obj['result'])


@cli.command(name='fix_index')
@click.argument('path')
@click.option('-d', '--destination', prompt='Where should I place the index?',
              help='d for destination')
@click.option('-o', '--overwrite', is_flag=True, default=False,
              help='Overwrite destination files')
def fix_index_command(path, destination, overwrite):
    """Recover index for blob @PATH."""
    BlobRepairer.recover_index(DataFile(path), destination, overwrite)


@cli.command(name='fix_blob')
@click.argument('path')
@click.option('-d', '--destination', prompt='Where should I place results?',
              help='d for destination')
@click.option('-y', '--yes', 'noprompt', is_flag=True, default=False,
              help='Assume Yes to all queries and do not prompt')
@click.option('-o', '--overwrite', is_flag=True, default=False,
              help='Overwrite destination files')
@click.pass_context
def fix_blob_command(ctx, path, destination, noprompt, overwrite):
    """Fix one blob @PATH.

    TODO(karapuz): get rid of noprompt and interactivity.

    """
    verbosity = ctx.obj.get('VERBOSITY', Verbosity.JSON)

    if verbosity <= Verbosity.JSON:
        noprompt = True

    if not os.path.exists(destination):
        os.mkdir(destination)

    blob_repairer = BlobRepairer(path)
    blob_repairer.fix(destination, noprompt, overwrite)

    # FIX_BLOB_STANDALONE - means that fix_blob_command not called from another subcommand.
    # TODO(karapuz): refactor ctx fields into well defined constants.
    if ctx.obj.get('FIX_BLOB_STANDALONE', True):
        dump_digest(verbosity, {path: blob_repairer.stat.as_digest_dict})
        dump_to_file(ctx.obj.get(JSON_OUTPUT), {path: blob_repairer.stat.as_dict})
    else:  # run as child.
        ctx.obj.setdefault(ReportType.EXTENDED, {})[path] = blob_repairer.stat.as_dict
        ctx.obj.setdefault(ReportType.BASIC, {})[path] = blob_repairer.stat.as_digest_dict


@cli.command(name='fix')
@click.argument('path')
@click.option('-d', '--destination', prompt='Where should I place results?',
              help='d for destination')
@click.option('-y', '--yes', 'noprompt', is_flag=True, default=False,
              help="Assume Yes to all queries and do not prompt, "
              "will be switched on when verbosity option not set")
@click.option('-o', '--overwrite', is_flag=True, default=False,
              help='Overwrite destination files')
@click.pass_context
def fix_command(ctx, path, destination, noprompt, overwrite):
    """Fix blobs @PATH."""
    verbosity = ctx.obj.get('VERBOSITY', Verbosity.JSON)

    if verbosity <= Verbosity.JSON:
        noprompt = True

    ctx.obj['FIX_BLOB_STANDALONE'] = False

    for blob in files(path):
        try:
            ctx.invoke(fix_blob_command, path=blob, destination=destination, noprompt=noprompt, overwrite=overwrite)
        except Exception as exc:
            logging.error('Failed to fix %s: %s', blob, exc)
            raise

    results = ctx.obj.get(ReportType.EXTENDED, {})
    results_digest = ctx.obj.get(ReportType.BASIC, {})

    # Put basic stat to stdout.
    dump_digest(verbosity, results_digest)
    dump_to_file(ctx.obj.get(JSON_OUTPUT), results)

@cli.command(name='find_duplicates')
@click.argument('path')
@click.pass_context
def find_duplicates_command(ctx, path):
    try:
        duplicates = find_duplicates(files(path))
        ctx.exit(1 if len(duplicates) != 0 else 0)
    except Exception:
        logging.exception('Failed to find duplicates')
        ctx.exit(errno.EIO)


@cli.command(name='remove_duplicates')
@click.argument('path')
@click.pass_context
def remove_duplicates_command(ctx, path):
    remove_duplicates(files(path))


@cli.command(name='restore_keys')
@click.argument('path')
@click.option('-k', '--keys', 'keys_path', prompt='Where should I found keys to resotre',
              help='k for keys to restore')
@click.option('--short', is_flag=True)
@click.option('--checksum-type', type=click.Choice([ChecksumTypes.SHA512, ChecksumTypes.CHUNKED]), default=None,
              help=('specify checksum-type to avoid checksum recognition. ATTENTION! IF YOU CHOOSE WRONG CHECKSUM TYPE,'
                    ' RESTORED RECORDS WILL BE CONSIDERED AS CORRUPTED. SO, PLEASE, USE IT WITH CAUTION!'))
@click.pass_context
def restore_keys_command(ctx, path, keys_path, short, checksum_type):
    ctx.exit(
        not restore_keys(blobs=files(path),
                         keys=read_keys(keys_path, short),
                         short=short,
                         checksum_type=checksum_type)
    )


def main():
    """Main function."""
    cli(obj={})

if __name__ == '__main__':
    main()
