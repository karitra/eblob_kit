"""Tests for eblob_kit.get_checksum_size."""
import pytest

from common import make_header

from eblob_kit import get_checksum_size
from eblob_kit import RecordFlags


# Marginal cases of header.data_size parameters.
marginal_data_sizes = [0, 1, 2, 3, 1 << 20, 1 << 20 + 1, (1 << 20) * 2 + 1]


@pytest.mark.parametrize('data_size, checksum_size', [
    # TODO(karapuz): is data_size == 0 valid?
    (0, 8),
    (1, 16),
    (1, 16),
    (2, 16),
    (3, 16),
    (1 << 20, 16),
    (1 << 20 + 1, 24),
    ((1 << 20) * 2 + 1, 32),
])
def test_get_checksum_size_for_chunked_csum(data_size, checksum_size):
    """Count checksum for headers with CHUNKED_CSUM flag."""
    header = make_header(data_size=data_size, flags=RecordFlags(RecordFlags.CHUNKED_CSUM))
    assert get_checksum_size(header) == checksum_size


@pytest.mark.parametrize('data_size', marginal_data_sizes)
def test_get_checksum_size_for_nocsum(data_size):
    """Count checksum for headers with CHUNKED_CSUM flag.

    No metter what is data_size of header, checksum size should be zero.
    """
    header = make_header(data_size=data_size, flags=RecordFlags(RecordFlags.NOCSUM))
    assert get_checksum_size(header) == 0


@pytest.mark.parametrize('data_size', marginal_data_sizes)
def test_get_checksum_size_noflags(data_size):
    """Count checksum for headers with no influencing flags set."""
    header = make_header(data_size=data_size, flags=RecordFlags(0))
    assert get_checksum_size(header) == 64
