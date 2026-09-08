import pytest

from recon.modules.ports import TOP_PORTS, parse_ports


def test_top_keyword():
    assert parse_ports("top") == TOP_PORTS
    assert parse_ports(None) == TOP_PORTS


def test_single_port():
    assert parse_ports("443") == [443]


def test_comma_list_sorted_and_deduped():
    assert parse_ports("443,80,80,22") == [22, 80, 443]


def test_range():
    assert parse_ports("20-25") == [20, 21, 22, 23, 24, 25]


def test_reversed_range_is_normalised():
    assert parse_ports("25-20") == [20, 21, 22, 23, 24, 25]


def test_mixed_spec():
    assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]


def test_out_of_range_clamped():
    assert parse_ports("65530-70000") == [65530, 65531, 65532, 65533, 65534, 65535]


def test_invalid_raises():
    with pytest.raises(ValueError):
        parse_ports("http")
