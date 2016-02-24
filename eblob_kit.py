#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Toolkit for working with eblob blobs."""

import logging
import glob
import re
import os
import struct
import hashlib

import pyhash
import click

logging.basicConfig(filename='log.log',
                    format='%(asctime)s %(process)d %(levelname)s: %(message)s',
                    level=logging.DEBUG)


class ExtensionHeader(object):
    """Elliptics extension header."""

    size = 48


class RecordFlags(object):
    """Record flags."""

    REMOVED = 1 << 0
    NOCSUM = 1 << 1
    EXTHDR = 1 << 6
    UNCOMMITTED = 1 << 7
    CHUNKED_CSUM = 1 << 8

    _FLAGS = {
        REMOVED: 'removed',
        NOCSUM: 'nocsum',
        EXTHDR: 'exthdr',
        UNCOMMITTED: 'uncommitted',
        CHUNKED_CSUM: 'chunked_csum',
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

    def __init__(self, data):
        """Initialize from raw @data and @offset."""
        assert len(data) == DiskControl.size
        self.key = data[:64]
        raw = struct.unpack('4Q', data[64:])
        self.flags = RecordFlags(raw[0])
        self.data_size = raw[1]
        self.disk_size = raw[2]
        self.position = raw[3]

    @property
    def raw_data(self):
        """Convert DiskControl to raw format."""
        raw = struct.pack('4Q', self.flags.flags, self.data_size, self.disk_size, self.position)
        return self.key + raw

    def __nonzero__(self):
        """Return true if self is valid."""
        return self.data_size != 0 and self.disk_size != 0

    def __str__(self):
        """Make human-readable string."""
        return '{}: position: {:12} data_size: {} ({}) disk_size: {} ({}) flags: {}'.format(
            self.key.encode('hex'), self.position,
            self.data_size, sizeof_fmt(self.data_size),
            self.disk_size, sizeof_fmt(self.disk_size),
            self.flags)

    def __cmp__(self, other):
        """Compare self with other."""
        return cmp((self.key, self.flags, self.data_size, self.disk_size, self.position),
                   (other.key, other.flags, other.data_size, other.disk_size, other.position))


class IndexFile(object):
    """Abstraction to index file."""

    def __init__(self, path):
        """Initialize IndexFile object again @path."""
        if path.endswith('.index.sorted'):
            self.sorted = True
        elif path.endswith('.index'):
            self.sorted = False
        else:
            raise RuntimeError('{} is not index'.format(path))
        self._file = open(path, 'r+')

    @staticmethod
    def create(path):
        """Create IndexFile for @path."""
        open(path, 'a').close()
        return IndexFile(path)

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

    def __len__(self):
        """Return number of headers in index file."""
        return self.size() / DiskControl.size

    def __iter__(self):
        """Iterate over headers in the index."""
        self._file.seek(0)
        while True:
            offset = self._file.tell()
            data = self._file.read(DiskControl.size)
            if len(data) == 0:
                break
            if len(data) != DiskControl.size:
                raise EOFError('Failed to read header at offset {} of {} ({})'
                               .format(offset, self.path, self.size()))
            yield DiskControl(data)


class DataFile(object):
    """Abstraction to data file."""

    def __init__(self, path):
        """Initialize DataFile object again @path."""
        self.sorted = os.path.exists(path + '.data_is_sorted') and \
            os.path.exists(path + '.index.sorted')
        self._file = open(path, 'r+')

    @property
    def path(self):
        """Return path to the data file."""
        return self._file.name

    @property
    def file(self):
        """Return file."""
        return self._file

    def read_header(self, offset):
        """Read DiskControl at @offset."""
        return DiskControl(self.read(offset, DiskControl.size))

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

    def __init__(self, path):
        """Initialize Blob object again @path."""
        if os.path.exists(path + '.index.sorted'):
            self._index_file = IndexFile(path + '.index.sorted')
        elif os.path.exists(path + '.index'):
            self._index_file = IndexFile(path + '.index')
        else:
            raise IOError('Could not find index for {}'.format(path))
        self._data_file = DataFile(path)

    @staticmethod
    def create(path):
        """Create new Blob at @path."""
        open(path + '.index', 'a').close()
        open(path, 'a').close()
        return Blob(path)

    @property
    def index(self):
        """Return index file."""
        return self._index_file

    @property
    def data(self):
        """Return data file."""
        return self._data_file


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
    """Print error text into console."""
    click.secho(text, bold=True, fg='red', err=True)
    logging.error(text)


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
    new_header = header.key + struct.pack('4Q', header.flags.flags, header.data_size,
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


class BlobRepairer(object):
    """Check and repair blob."""

    def __init__(self, path):
        """Initialize BlobRepairer for blob at @path."""
        self.blob = Blob(path)
        self.valid = True
        self.index_order_error = False
        self.invalid_index_size = False
        self.index_malformed_headers = 0
        self.index_headers = []
        self.corrupted_data_headers = 0
        self.corrupted_data_headers_size = 0
        self.index_removed_headers = 0
        self.index_removed_headers_size = 0
        self.data_recoverable_headers = []
        self.mismatched_headers = []
        self.holes = 0
        self.holes_size = 0

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

        if header.data_size == 0 and not header.flags.uncommitted:
            logging.error('malformed header has empty data_size but it is committed: %s', header)
            return False

        if not header.flags.uncommitted:
            extension_header_size = ExtensionHeader.size if header.flags.exthdr else 0
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
                data_header = self.blob.data.read_header(position)
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
                print_error('Header from data defines record as %s that is beyond the hole %s'
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
                if not data_header.flags.removed:
                    self.data_recoverable_headers.append(data_header)
                position += data_header.disk_size

        if position != end:
            self.holes += 1
            self.holes_size += end - position

    def resolve_mispositioned_record(self, header_idx, position, valid_headers):
        """
        Try to resolve mispositioned record failure.

        Return whether header at @header_idx should be skipped.
        """
        header = self.index_headers[header_idx]

        assert header_idx > 0, 'Mispositioned record failure can not occur with first header'
        previous_header = self.index_headers[header_idx - 1]
        assert position == previous_header.position + previous_header.disk_size,\
            'Previous header should be placed exactly before position'
        assert previous_header.position <= header.position, 'Headers should be sorted by position'

        data_header = self.blob.data.read_header(header.position)

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

    def check_index(self):
        """Check that index file is correct."""
        prev_key = None
        try:
            with click.progressbar(iter(self.blob.index), length=len(self.blob.index),
                                   label='Checking {}'.format(self.blob.index.path)) as pbar:
                for header in pbar:
                    if self.check_header(header):
                        self.index_headers.append(header)
                        if prev_key and self.blob.index.sorted:
                            if prev_key > header.key:
                                self.valid = False
                                self.blob.index.sorted = False
                                self.index_order_error = True
                            prev_key = header.key
                    else:
                        self.index_malformed_headers += 1
                        self.valid = False
        except EOFError as exc:
            print_error('{} has incorrect size ({}) which is not a multiple '
                        'of DiskControl.size ({}). Last incomplete header ({}) will be ignored.'
                        .format(self.blob.index.path, self.blob.index.size(), DiskControl.size,
                                self.blob.index.size() % DiskControl.size))
            logging.error('Failed to read header: %s. Skip other headers in index', exc)
            self.invalid_index_size = True
            self.valid = False

        if self.index_order_error:
            print_error('{} is supposed to be sorted, but it has disordered headers'.format(
                self.blob.index.path))

        if self.index_malformed_headers or self.invalid_index_size:
            print_error('{} has {} malformed and {} valid headers'.format(
                self.blob.index.path, self.index_malformed_headers, len(self.index_headers)))
        else:
            logging.info('All %d headers in %s are valid',
                         len(self.index_headers), self.blob.index.path)

        self.index_headers = sorted(self.index_headers, key=lambda h: h.position)

    def print_check_report(self):
        """Print report after check."""
        if self.valid:
            click.secho('{} is valid'.format(self.blob.data.path), bold=True)
            return

        report = '{} has:'.format(self.blob.data.path)
        report += '\n\t{} headers from index are valid'.format(len(self.index_headers))
        if self.index_removed_headers:
            report += '\n\t{} headers ({}) from index are valid and marked as removed'.format(
                self.index_removed_headers, sizeof_fmt(self.index_removed_headers_size))

        if self.mismatched_headers:
            report += '\n\t{} headers which are different in the blob and in the index'.format(
                len(self.mismatched_headers))

        if self.data_recoverable_headers:
            report += '\n\t{} headers can be recovered from data'.format(
                len(self.data_recoverable_headers))
        if self.holes:
            report += '\n\t{} holes ({}) in blob which are not marked'.format(
                self.holes, sizeof_fmt(self.holes_size))
        if self.index_order_error:
            report += '\n\t{} is supposed to be sorted but it has disordered header'.format(
                self.blob.index.path)
        if self.corrupted_data_headers:
            report += '\n\t{} headers ({}) has corrupted data'.format(
                self.corrupted_data_headers, sizeof_fmt(self.corrupted_data_headers_size))
        print_error(report)

        if not self.index_headers:
            print_error('{} does not match {}'.format(self.blob.index.path,
                                                      self.blob.data.path))

    def verify_sha15(self, header):
        """Verify sha512 checksum of the record pointer by @header."""
        self.blob.data.file.seek(header.position + DiskControl.size)

        length = header.data_size
        chunk = 32768
        hasher = hashlib.sha512()
        while length:
            chunk = min(length, chunk)
            hasher.update(self.blob.data.file.read(chunk))
            length -= chunk

        calculated_csum = hasher.digest()

        footer_size = 64 + 8

        self.blob.data.file.seek(header.position + header.disk_size - footer_size)
        stored_csum = self.blob.data.file.read(footer_size)[:64]

        if calculated_csum != stored_csum:
            print_error('Invalid csum, stored ({}) != calculated ({}): {}'.format(
                stored_csum.encode('hex'), calculated_csum.encode('hex'), header))
            return False
        return True

    def murmur_chunk(self, chunk):
        """Apply murmurhash to chunk and return raw result."""
        chunk_size = 4096
        result = 0
        hasher = pyhash.murmur2_x64_64a()
        while chunk:
            result = hasher(chunk[:chunk_size], seed=result)
            chunk = chunk[chunk_size:]
        return struct.pack('Q', result)

    def murmur_record_data(self, header, chunk_size):
        """Apply murmurhash to record's data pointed by @header."""
        self.blob.data.file.seek(header.position + DiskControl.size)

        length = header.data_size
        while length:
            chunk_size = min(length, chunk_size)
            yield self.murmur_chunk(self.blob.data.file.read(chunk_size))
            length -= chunk_size

    def verify_chunked(self, header):
        """Verify chunked checksum of the record pointer by @header."""
        footer_size = 8

        chunk_size = 1 << 20
        chunks_count = ((header.disk_size - DiskControl.size - footer_size - 1) / (chunk_size + footer_size)) + 1
        footer_offset = header.position + header.disk_size - (chunks_count + 1) * footer_size

        calculated_csum = ''.join(self.murmur_record_data(header, chunk_size))

        self.blob.data.file.seek(footer_offset)
        stored_csum = self.blob.data.file.read(len(calculated_csum))
        if calculated_csum != stored_csum:
            print_error('Invalid csum, stored ({}) != calculated ({}): {}'.format(
                stored_csum.encode('hex'), calculated_csum.encode('hex'), header))
            return False
        return True

    def verify_csum(self, header):
        """Verify checksum of the record pointed by @header."""
        if header.flags.nocsum:
            return True

        if header.flags.chunked_csum:
            return self.verify_chunked(header)
        else:
            return self.verify_sha15(header)

    def check(self, verify_csum):
        """Check that both index and data files are correct."""
        self.check_index()

        valid_headers = []

        with click.progressbar(enumerate(self.index_headers),
                               length=len(self.index_headers),
                               label='Checking: {}'.format(self.blob.data.path)) as pbar:
            position = 0
            for header_idx, index_header in pbar:
                if position > index_header.position:
                    self.resolve_mispositioned_record(header_idx, position, valid_headers)

                if position < index_header.position:
                    self.valid = False
                    self.check_hole(position, index_header.position)

                data_header = self.blob.data.read_header(index_header.position)
                if index_header == data_header:
                    if not index_header.flags.removed:
                        if verify_csum:
                            if self.verify_csum(index_header):
                                valid_headers.append(index_header)
                            else:
                                self.corrupted_data_headers += 1
                                self.corrupted_data_headers_size += index_header.disk_size
                        else:
                            valid_headers.append(index_header)
                    else:
                        self.index_removed_headers += 1
                        self.index_removed_headers_size += index_header.disk_size
                else:
                    self.resolve_mismatch(index_header, data_header, valid_headers)
                position = index_header.position + index_header.disk_size

            if position < len(self.blob.data):
                self.valid = False
                self.check_hole(position, len(self.blob.data))

        self.index_headers = valid_headers

        self.print_check_report()

    @staticmethod
    def recover_index(data, destination):
        """Recover index from data."""
        basename = os.path.basename(data.path)
        index_path = os.path.join(destination, basename + '.index')
        index = IndexFile.create(index_path)

        with click.progressbar(length=len(data),
                               label='Recovering index {} -> {}'
                               .format(data.path, index_path)) as pbar:
            for header in data:
                if not header:
                    offset = data.file.tell() - DiskControl.size
                    print_error('I have found broken header at offset {}: {}'
                                .format(offset, header))
                    print_error('This record can not be skipped, so I break the recovering. '
                                'You can use {} as an index for {} but id does not include '
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

        with click.progressbar(length=len(self.blob.data),
                               label='Recovering blob {} -> {}'
                               .format(self.blob.data.path, blob_path)) as pbar:
            for header in self.blob.data:
                if not header:
                    print_error('I have faced with broken record which I can not skip.')
                if not header:
                    skipped_records += 1
                elif header.flags.removed:
                    removed_records += 1
                else:
                    copy_record(self.blob, blob, header)
                    copied_records += 1
                pbar.update(header.disk_size)
        click.echo('I have copied {} records, skipped {} and removed {} records'
                   .format(copied_records, skipped_records, removed_records))

    def copy_valid_records(self, destination):
        """Recover blob by copying only valid records from blob."""
        basename = os.path.basename(self.blob.data.path)
        blob_path = os.path.join(destination, basename)
        blob = Blob.create(blob_path)

        copied_records = 0
        copied_size = 0

        with click.progressbar(iter(self.index_headers),
                               length=len(self.index_headers),
                               label='Recovering blob {} -> {}'
                               .format(self.blob.data.path, blob_path)) as pbar:
            for header in pbar:
                copy_record(self.blob, blob, header)
                copied_records += 1
                copied_size += header.disk_size
        click.echo('I have copied {} ({}) records {} -> {} '.format(
            copied_records, sizeof_fmt(copied_size), self.blob.data.path, blob_path))

    def fix(self, destination):
        """Check blob's data & index and try to fix them if they are broken."""
        self.check(True)

        if self.valid:
            return

        if not self.index_headers:
            if click.confirm('There is no valid header in {}. '
                             'Should I try to recover index from {}?'
                             .format(self.blob.index.path, self.blob.data.path),
                             default=True):
                self.recover_index(self.blob.data, destination)
            elif click.confirm('Should I try to recover both index and data from {}?'
                               .format(self.blob.data.path),
                               default=True):
                self.recover_blob(destination)
        else:
            if click.confirm('I can repair {}?'.format(self.blob.data.path),
                             default=True):
                self.copy_valid_records(destination)


@click.group()
@click.version_option(version='0.0.1')
def cli():
    """eblob_kit is the tool for diagnosing, recovering and listing blobs."""


@cli.command(name='list_index')
@click.argument('path')
def list_index_command(path):
    """List index file specified by @PATH."""
    assert os.path.exists(path), 'Failed to listing index: {}: file does not exist'.format(path)
    for header in IndexFile(path):
        click.echo(header)


@cli.command(name='list_data')
@click.argument('path')
def list_data_command(path):
    """List data file specified by @PATH."""
    assert os.path.exists(path), 'Failed to listing data: {}: failed does not exist'.format(path)
    for header in DataFile(path):
        click.echo(header)


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
def check_blob_command(path, verify_csum):
    """Check that blob (its data and index) is correct."""
    try:
        BlobRepairer(path).check(verify_csum)
    except IOError as exc:
        print_error('I have failed to open {}: {}'.format(path, exc))


@cli.command(name='check')
@click.argument('path')
@click.option('-V', '--verify-csum', is_flag=True, default=False, help='V for verify checksum')
@click.pass_context
def check_command(ctx, path, verify_csum):
    """Check that all blobs (datas and indexes) are correct."""
    for blob_path in files(path):
        ctx.invoke(check_blob_command, path=blob_path, verify_csum=verify_csum)


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
def fix_blob_command(path, destination):
    """Fix one blob @PATH."""
    if not os.path.exists(destination):
        os.mkdir(destination)

    BlobRepairer(path).fix(destination)


@cli.command(name='fix')
@click.argument('path')
@click.option('-d', '--destination', prompt='Where should I place results?',
              help='d for destination')
@click.pass_context
def fix_command(ctx, path, destination, step_over):
    """Fix blobs @PATH."""
    for blob in files(path):
        try:
            ctx.invoke(fix_blob_command, path=blob, destination=destination)
        except Exception as exc:
            print_error('Failed to fix {}: {} '.format(blob, exc))

if __name__ == '__main__':
    cli()
