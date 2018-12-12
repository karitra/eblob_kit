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
import sys
import struct
from datetime import datetime
from datetime import timedelta

import click
import pyhash

LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s: %(message)s'


class MutedProgressbar(object):
    """Mute progressbar output when in MM minion mode.

    TODO(karapuz): it seems, that with some additional tweaks it is possible to
    add progressbar to Mastermaind Minion watcher, so minion progress would be
    indicated in dashboard.
    """
    def __init__(self, iterator=None):
        self._iterator = iterator

    def __enter__(self):
        class DummyProgressIterator(object):
            def __init__(self, **kwargs):
                self._iterator = kwargs.get('iterator')

            def __iter__(self):
                return self

            def update(*_args):
                pass

            def next(self):
                if self._iterator:
                    return self._iterator.next()

                raise StopIteration

        return DummyProgressIterator(iterator=self._iterator)

    def __exit__(_self, *_args):
        pass


def make_progressbar(is_minion_mode, length, label, iterator=None):
    if is_minion_mode:
        return MutedProgressbar(iterator)
    elif iterator is None:
        return click.progressbar(length=length, label=label)
    else:
        return click.progressbar(iterator, length=length, label=label)


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
    """Elliptics extension header."""

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
    """Eblob record header."""

    size = 96
    key_size = 64

    def __init__(self, data):
        """Initialize from raw @data and @offset."""
        assert len(data) == DiskControl.size
        self.key = data[:self.key_size]
        raw = struct.unpack('<4Q', data[self.key_size:])
        self.flags = RecordFlags(raw[0])
        self.data_size = raw[1]
        self.disk_size = raw[2]
        self.position = raw[3]

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
            self.key_as_string, self.position,
            self.data_size, sizeof_fmt(self.data_size),
            self.disk_size, sizeof_fmt(self.disk_size),
            self.flags)

    def __cmp__(self, other):
        """Compare self with other."""
        return cmp((self.key, self.flags, self.data_size, self.disk_size, self.position),
                   (other.key, other.flags, other.data_size, other.disk_size, other.position))

    @property
    def key_as_string(self):
        return self.key.encode('hex')


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
        """Create IndexFile for @path."""
        open(path, 'ab').close()
        return IndexFile(path, mode='ab')

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
        return DiskControl(self._file.read(DiskControl.size))

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
            yield DiskControl(data)


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
        return DiskControl(self.read(position, DiskControl.size))

    def read_elliptics_header(self, position):
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
            header = DiskControl(data)
            yield header
            self._file.seek(offset + header.disk_size)

    def __len__(self):
        """Return size of data file."""
        return os.fstat(self._file.fileno()).st_size


class Blob(object):
    """Abstraction to blob consisted from index and data files."""

    def __init__(self, path, mode='rb', is_minion_mode=False):
        """Initialize Blob object again @path."""
        if os.path.exists(path + '.index.sorted'):
            self._index_file = IndexFile(path + '.index.sorted', mode)
        elif os.path.exists(path + '.index'):
            self._index_file = IndexFile(path + '.index', mode)
        else:
            raise IOError('Could not find index for {}'.format(path))

        self._data_file = DataFile(path, mode)
        self._eprint = (
            LoggerOnlyErrorPrinter() if is_minion_mode
            else BaseErrorPrinter()
        )

    @staticmethod
    def create(path):
        """Create new Blob at @path."""
        open(path + '.index', 'ab').close()
        open(path, 'ab').close()
        return Blob(path, 'ab')

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
            self._eprint(
                'Invalid csum, stored ({}) != calculated ({}): {}'.format(
                stored_csum.encode('hex'), calculated_csum.encode('hex'), header))
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
            self._eprint('Invalid csum, stored ({}) != calculated ({}): {}'.format(
                stored_csum.encode('hex'), calculated_csum.encode('hex'), header))
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


def print_error(text):
    """Print error text into console and log."""
    click.secho(text, bold=True, fg='red', err=True)
    logging.error(text)


# TODO(karapuz): implement print_info conterparts?
class BaseErrorPrinter(object):
    """Adapter to basic print_error function."""
    def __call__(self, error_text):
        print_error(error_text)


class LoggerOnlyErrorPrinter(object):
    """Prints error only to log file."""
    def __call__(self, error_text):
        logging.error(error_text)


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


class BlobRepairer(object):
    """Check and repair blob."""

    def __init__(self, path, is_minion_mode=False):
        """Initialize BlobRepairer for blob at @path."""
        self.blob = Blob(path, is_minion_mode=is_minion_mode)
        self.valid = True
        self.index_order_error = False
        self.invalid_index_size = False
        self.index_malformed_headers = 0
        self.index_malformed_headers_keys = set()
        self.index_headers = []
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
        self.is_minion_mode = is_minion_mode

        self.eprint = (
            LoggerOnlyErrorPrinter() if is_minion_mode
            else BaseErrorPrinter()
        )

    @property
    def artifacts(self):
        """Compose MasterMind minion artifacts."""

        return {
            'index_order_error': self.index_order_error,
            'invalid_index_size': self.invalid_index_size,

            'index_malformed_headers': self.index_malformed_headers,
            'index_malformed_headers_keys': list(self.index_malformed_headers_keys),

            'corrupted_data_headers': self.corrupted_data_headers,
            'corrupted_data_headers_keys': list(self.corrupted_data_headers_keys),

            'index_removed_headers': self.index_removed_headers,
            'index_removed_headers_keys': list(self.index_removed_headers_keys),

            'index_uncommitted_headers': self.index_uncommitted_headers,
            'index_uncommitted_headers_keys': list(self.index_uncommitted_headers_keys),

            'data_recoverable_headers_keys': [
                k.key_as_string for k in self.data_recoverable_headers
            ],

            'mismatched_headers': [d.key_as_string for _, d in self.mismatched_headers],
        }

    def check_header(self, header):
        """Check header correctness."""
        if header.disk_size == 0:
            logging.error('malformed header has empty disk_size: %s', header)
            return False

        if header.position + header.disk_size > len(self.blob.data):
            logging.error('malformed header has position (%d) + disk_size (%d) '
                          'is out of %s (%d): %s',
                          header.position, header.disk_size,
                          self.blob.data.path, len(self.blob.data), header)
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
                data_header = self.blob.data.read_disk_control(position)
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
                self.eprint('Header from data defines record as %s that is beyond the hole %s'
                            'Currently, I can not overcome this type of failure, '
                            'so I skip headers from data in {}'
                            .format(header_range_fmt(data_header),
                                    range_fmt(position, end),
                                    range_fmt(position, end)))
                logging.error('Header (%s) is beyond the hole %s: %s',
                              header_range_fmt(data_header), range_fmt(position, end),
                              data_header)
                break
            else:
                logging.info('I have found valid header at position %d in data and '
                             'will add it to headers list', position)
                if not data_header.flags.removed and not data_header.flags.uncommitted:
                    self.data_recoverable_headers.append(data_header)
                position += data_header.disk_size

        if position != end:
            self.holes += 1
            self.holes_size += end - position


    def resolve_mispositioned_record(self, header_idx, position, valid_headers):
        """Try to resolve mispositioned record failure.

        Return whether header at @header_idx should be skipped.
        """
        header = self.index_headers[header_idx]

        # TODO(karapuz): errors instead of asserts?
        assert \
            header_idx > 0, \
            'Mispositioned record failure can not occur with first header'

        previous_header = self.index_headers[header_idx - 1]
        assert \
            position == previous_header.position + previous_header.disk_size, \
            'Previous header should be placed exactly before position'

        assert \
            previous_header.position <= header.position, \
            'Headers should be sorted by position'

        data_header = self.blob.data.read_disk_control(header.position)

        if header != data_header:
            logging.error('Mispositioned record does not match header from data. Skip it: %s',
                          header)
            return True
        elif valid_headers and valid_headers[-1] == previous_header:
            logging.error('Mispositioned record does match header from data, so I remove '
                          'previous conflicting record which was correct. '
                          'current: %s, previous: %s', header, previous_header)
            del valid_headers[-1]
        elif self.mismatched_headers and self.mismatched_headers[-1][0] == previous_header:
            logging.error('Mispositioned record does match header from data, so I remove '
                          'previous conflicting record which was mismatched. '
                          'current: %s, previous: %s', header, previous_header)
            del self.mismatched_headers[-1]
        return False

    def resolve_mismatch(self, index_header, data_header, valid_headers):
        """Try to resolve mismatch if it is detected."""
        self.mismatched_headers.append((index_header, data_header))
        self.valid = False

        logging.error('Headers mismatches: data_header: %s, index_header: %s',
                      data_header, index_header)

    def check_index(self, fast):
        """Check that index file is correct."""
        prev_key = None
        try:
            stat_chunk = 1 << 15
            with make_progressbar(
                self.is_minion_mode,
                length=len(self.blob.index),
                label='Checking {}'.format(self.blob.index.path)
            ) as pbar:
                for index, header in enumerate(self.blob.index, 1):
                    if fast and not self.valid:
                        # return if it is fast-check and there was an error
                        return
                    if self.check_header(header):
                        self.index_headers.append(header)
                        if prev_key and self.blob.index.sorted:
                            if prev_key > header.key:
                                self.valid = False
                                self.blob.index.sorted = False
                                self.index_order_error = True
                            prev_key = header.key
                    else:
                        self.index_malformed_headers_keys.add(header.key_as_string)
                        self.index_malformed_headers += 1
                        self.valid = False
                    if index % stat_chunk == 0:
                        pbar.update(stat_chunk)
                pbar.update(stat_chunk)
        except EOFError as exc:
            self.eprint('{} has incorrect size ({}) which is not a multiple '
                        'of DiskControl.size ({}). Last incomplete header ({}) will be ignored.'
                        .format(self.blob.index.path, self.blob.index.size(), DiskControl.size,
                                self.blob.index.size() % DiskControl.size))
            logging.error('Failed to read header: %s. Skip other headers in index', exc)
            self.invalid_index_size = True
            self.valid = False

        if fast and not self.valid:
            return

        if self.index_order_error:
            self.eprint('{} is supposed to be sorted, but it has disordered headers'.format(
                self.blob.index.path))

        if self.index_malformed_headers or self.invalid_index_size:
            self.eprint('{} has {} malformed and {} valid headers'.format(
                self.blob.index.path, self.index_malformed_headers, len(self.index_headers)))
        else:
            logging.info('All %d headers in %s are valid',
                         len(self.index_headers), self.blob.index.path)

        if not fast:
            self.index_headers = sorted(self.index_headers, key=lambda h: h.position)

    def print_check_report(self):
        """Print report after check."""
        if self.valid:
            report = '{} is valid and has:'.format(self.blob.data.path)
            report += '\n\t{} valid records'.format(len(self.index_headers))
            report += '\n\t{} removed records ({})'.format(
                self.index_removed_headers, sizeof_fmt(self.index_removed_headers_size))
            report += '\n\t{} uncommitted records ({})'.format(
                self.index_uncommitted_headers, sizeof_fmt(self.index_uncommitted_headers_size))
            if self.is_minion_mode:
                logging.info(report)
            else:
                click.secho(report, bold=True)
            return

        report = '{} has:'.format(self.blob.data.path)
        report += '\n\t{} headers ({}) from index are valid'.format(
            len(self.index_headers), sizeof_fmt(sum(h.disk_size for h in self.index_headers)))
        if self.index_removed_headers:
            report += '\n\t{} headers ({}) from index are valid and marked as removed'.format(
                self.index_removed_headers, sizeof_fmt(self.index_removed_headers_size))
        if self.index_uncommitted_headers:
            report += '\n\t{} headers ({}) from index are valid and marked as uncommitted'.format(
                self.index_uncommitted_headers, sizeof_fmt(self.index_uncommitted_headers_size))

        if self.mismatched_headers:
            report += '\n\t{} headers which are different in the blob and in the index'.format(
                len(self.mismatched_headers))

        if self.data_recoverable_headers:
            report += '\n\t{} headers ({}) can be recovered from data'.format(
                len(self.data_recoverable_headers),
                sizeof_fmt(sum(h.disk_size for h in self.data_recoverable_headers)))
        if self.holes:
            report += '\n\t{} holes ({}) in blob which are not marked'.format(
                self.holes, sizeof_fmt(self.holes_size))
        if self.index_order_error:
            report += '\n\t{} is supposed to be sorted but it has disordered header'.format(
                self.blob.index.path)
        if self.corrupted_data_headers:
            report += '\n\t{} headers ({}) has corrupted data'.format(
                self.corrupted_data_headers, sizeof_fmt(self.corrupted_data_headers_size))
        self.eprint(report)

        if (not self.index_headers and
                not self.index_removed_headers and
                not self.index_uncommitted_headers):
            self.eprint('{} does not match {}'.format(self.blob.index.path,
                                                      self.blob.data.path))

    def check(self, verify_csum, fast):
        """Check that both index and data files are correct."""
        self.check_index(fast=fast)

        if fast:
            return self.valid

        valid_headers = []

        stat_chunk = 1 << 15

        with make_progressbar(
            self.is_minion_mode,
            length=len(self.index_headers),
            label='Checking: {}'.format(self.blob.data.path)
        ) as pbar:
            position = 0
            for header_idx, index_header in enumerate(self.index_headers):
                if position > index_header.position:
                    self.resolve_mispositioned_record(header_idx, position, valid_headers)

                if position < index_header.position:
                    self.valid = False
                    self.check_hole(position, index_header.position)

                data_header = self.blob.data.read_disk_control(index_header.position)
                if index_header == data_header:
                    if index_header.flags.removed:
                        self.index_removed_headers += 1
                        self.index_removed_headers_keys.add(data_header.key_as_string)
                        self.index_removed_headers_size += index_header.disk_size
                    elif index_header.flags.uncommitted:
                        self.index_uncommitted_headers += 1
                        self.index_uncommitted_headers_keys.add(data_header.key_as_string)
                        self.index_uncommitted_headers_size += index_header.disk_size
                    else:
                        if verify_csum:
                            if not self.blob.verify_csum(index_header):
                                self.corrupted_data_headers += 1
                                self.corrupted_data_headers_keys.add(data_header.key_as_string)
                                self.corrupted_data_headers_size += index_header.disk_size
                                self.valid = False
                            else:
                                valid_headers.append(index_header)
                        else:
                            valid_headers.append(index_header)
                else:
                    self.resolve_mismatch(index_header, data_header, valid_headers)
                position = index_header.position + index_header.disk_size

                if (header_idx + 1) % stat_chunk == 0:
                    pbar.update(stat_chunk)

            pbar.update(stat_chunk)

            if position < len(self.blob.data):
                self.valid = False
                self.check_hole(position, len(self.blob.data))

        self.index_headers = valid_headers

        return self.valid

    @staticmethod
    def recover_index(data, destination):
        """Recover index from data."""
        basename = os.path.basename(data.path)
        index_path = os.path.join(destination, basename + '.index')
        index = IndexFile.create(index_path)

        with make_progressbar(
            self.is_minion_mode,
            length=len(data),
            label='Recovering index {} -> {}'.format(data.path, index_path)
        ) as pbar:
            for header in data:
                if not header:
                    offset = data.file.tell() - DiskControl.size
                    self.eprint('I have found broken header at offset {}: {}'
                                .format(offset, header))
                    self.eprint('This record can not be skipped, so I break the recovering. '
                                'You can use {} as an index for {} but it does not include '
                                'records after {} offset'.format(index.path, data.path,
                                                                 offset))
                    break
                index.append(header)
                pbar.update(header.disk_size)

    def recover_blob(self, destination):
        """Recover blob from data."""
        basename = os.path.basename(self.blob.data.path)
        blob_path = os.path.join(destination, basename)
        blob = Blob.create(blob_path)

        copied_records = 0
        removed_records = 0
        skipped_records = 0

        with make_progressbar(
            self.is_minion_mode,
            length=len(self.blob.data),
            label='Recovering blob {} -> {}'.format(self.blob.data.path, blob_path)
        ) as pbar:
            for header in self.blob.data:
                if not header:
                    self.eprint('I have faced with broken record which I can not skip.')
                if not header:
                    skipped_records += 1
                elif header.flags.removed:
                    removed_records += 1
                else:
                    copy_record(self.blob, blob, header)
                    copied_records += 1
                pbar.update(header.disk_size)

        logger.info(
            'I have copied %s records, '
            'skipped %s and removed %s records',
            copied_records, skipped_records, removed_records
        )

    def copy_valid_records(self, destination):
        """Recover blob by copying only valid records from blob."""
        basename = os.path.basename(self.blob.data.path)
        blob_path = os.path.join(destination, basename)
        blob = Blob.create(blob_path)

        copied_records = 0
        copied_size = 0

        self.index_headers += self.data_recoverable_headers

        with make_progressbar(
            self.is_minion_mode,
            iterator=iter(self.index_headers),
            length=len(self.index_headers),
            label='Recovering blob {} -> {}'
            .format(self.blob.data.path, blob_path)
        ) as pbar:
            for header in pbar:
                copy_record(self.blob, blob, header)
                copied_records += 1
                copied_size += header.disk_size

        logging.info('I have copied {} ({}) records {} -> {} '.format(
            copied_records, sizeof_fmt(copied_size), self.blob.data.path,
            blob_path))

    def fix(self, destination, noprompt):
        """Check blob's data & index and try to fix them if they are broken."""
        self.check(verify_csum=True, fast=False)
        self.print_check_report()

        if self.valid:
            return

        if (not self.index_headers and
                not self.index_removed_headers and
                not self.index_uncommitted_headers):
            if noprompt:
                self.recover_blob(destination)
            elif click.confirm('There is no valid header in {}. '
                               'Should I try to recover index from {}?'
                               .format(self.blob.index.path, self.blob.data.path),
                               default=True):
                self.recover_index(self.blob.data, destination)
            elif click.confirm('Should I try to recover both index and data from {}?'
                               .format(self.blob.data.path),
                               default=True):
                self.recover_blob(destination)
        else:
            if not self.index_headers:
                self.eprint('Nothing can be recovered from {}, so it should be removed'
                            .format(self.blob.data.path))
                filname = '{}.should_be_removed'.format(
                    os.path.join(destination, os.path.basename(self.blob.data.path)))
                with open(filname, 'wb'):
                    pass
            elif noprompt or click.confirm('Should I repair {}?'.format(self.blob.data.path),
                                           default=True):
                self.copy_valid_records(destination)


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
        print_error(report)
    else:
        click.secho(report, bold=True)

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

        print_error('Duplicates removed: {}'.format(removed_duplicates))

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
@click.option('-l', '--log-file', default=None, help='File for logs')
def cli(ctx, log_file):
    """eblob_kit is the tool for diagnosing, recovering and listing blobs."""
    if log_file is None:
        logging.basicConfig(format=LOG_FORMAT, level=logging.ERROR)
    else:
        dir_name = os.path.dirname(os.path.abspath(log_file))
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
        logging.basicConfig(filename=log_file, format=LOG_FORMAT, level=logging.INFO)


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
        print_error('I have failed to open {}: {}'.format(path, exc))


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
def fix_index_command(path, destination):
    """Recover index for blob @PATH."""
    BlobRepairer.recover_index(DataFile(path), destination)


@cli.command(name='fix_blob')
@click.argument('path')
@click.option('-d', '--destination', prompt='Where should I place results?',
              help='d for destination')
@click.option('-y', '--yes', 'noprompt', is_flag=True, default=False,
              help='Assume Yes to all queries and do not prompt')
@click.option('-m', '--mmm-mode', 'is_minion', is_flag=True, default=False,
              help=("Run in mustermind minion mode: "
                    "'noprompt' flags would be set explicitly, "
                    "output is specially formatted JSON "
                    "and progress counters"))
def fix_blob_command(path, destination, noprompt, is_minion):
    """Fix one blob @PATH."""
    if is_minion:
        noprompt = True

    if not os.path.exists(destination):
        os.mkdir(destination)

    blob_repairer = BlobRepairer(path, is_minion)
    blob_repairer.fix(destination, noprompt)

    return blob_repairer.artifacts


@cli.command(name='fix')
@click.argument('path')
@click.option('-d', '--destination', prompt='Where should I place results?',
              help='d for destination')
@click.option('-y', '--yes', 'noprompt', is_flag=True, default=False,
              help='Assume Yes to all queries and do not prompt')
@click.option('-m', '--mmm-mode', 'is_minion', is_flag=True, default=False,
              help=("Run in MusterMind Minion mode: "
                    "'noprompt' flags would be set explicitly, "
                    "output is specially formatted JSON "
                    "and progress counters"))
@click.pass_context
def fix_command(ctx, path, destination, noprompt, is_minion):
    """Fix blobs @PATH."""
    if is_minion:
        noprompt = True

    err_print = LoggerOnlyErrorPrinter() if is_minion else BaseErrorPrinter()

    artifacts = {}
    for blob in files(path):
        try:
            artifacts[blob] = ctx.invoke(
                fix_blob_command,
                path=blob,
                destination=destination,
                noprompt=noprompt,
                is_minion=is_minion,
            )
        except Exception as exc:
            err_print('Failed to fix {}: {} '.format(blob, exc))
            raise

    if is_minion:
        json.dump(artifacts, sys.stdout)

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
