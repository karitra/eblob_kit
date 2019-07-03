import eblob_kit

from collections import namedtuple


DummyRecord = namedtuple('DummyRecord', 'a b')


def test_sequence_is_sorted_default_key():
    """Test that sequence is sorted with default key selector."""
    sorted_sequence = [-1, 1, 2, 3, 4, 5, 10, 100, 1000]
    assert eblob_kit.is_sorted(sorted_sequence)


def test_sequence_not_sorted_default_key():
    """Test that sequence is not sorted with default key selector."""
    non_sorted_sequence = [-1, 1, 2, 3, 4, 5, 10, 100, 99, 1000]
    assert not eblob_kit.is_sorted(non_sorted_sequence)


def test_sequence_is_sorted_custom_key():
    """Test sequence is sorted with custom field selector."""
    sequence_length = 5
    sequence = [
        DummyRecord(i, sequence_length - i) for i in xrange(sequence_length)
    ]

    assert eblob_kit.is_sorted(sequence)
    assert eblob_kit.is_sorted(sequence, lambda x: x.a)
    assert not eblob_kit.is_sorted(sequence, lambda x: x.b)
