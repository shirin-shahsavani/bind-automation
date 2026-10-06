import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from bind_manager import checker
from config.settings import settings


def test_check_record_type_valid():
    for rtype in ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "PTR"]:
        assert checker.check_record_type(rtype) is None


def test_check_record_type_invalid():
    with pytest.raises(HTTPException) as e:
        checker.check_record_type("WRONG")
    assert e.value.status_code == 404
    assert "type" in e.value.detail


@patch("bind_manager.checker.dns.resolver.Resolver")
def test_zone_existence_success(mock_resolver):
    instance = mock_resolver.return_value
    instance.resolve.return_value = True

    test_location = settings.locations_ip["test"]
    master = test_location["master"]

    assert checker.zone_existence("apple.com", master) is True
    instance.resolve.assert_called_once_with("apple.com", "SOA", lifetime=3)


@patch("bind_manager.checker.dns.resolver.Resolver")
def test_zone_existence_failure(mock_resolver):
    instance = mock_resolver.return_value
    instance.resolve.side_effect = Exception("fail")

    test_location = settings.locations_ip["test"]
    master = test_location["master"]

    with pytest.raises(HTTPException) as e:
        checker.zone_existence("apple1.com", master)
    assert e.value.status_code == 404
    assert "The zone does not exist or is not accessible." in str(e.value.detail)

@patch("bind_manager.checker.dns.zone.from_xfr")
@patch("bind_manager.checker.dns.query.xfr")
@patch("bind_manager.checker.dns.tsigkeyring.from_text")
def test_record_existence_found(mock_key, mock_xfr, mock_zone):
    fake_zone = MagicMock()
    fake_node = MagicMock()
    fake_node.rdatasets = [MagicMock(rdtype=1)]  # A record
    fake_zone.nodes.items.return_value = [("test", fake_node)]
    mock_zone.return_value = fake_zone

    test_location = settings.locations_ip["test"]
    master = test_location["master"]


    result = checker.record_existence("apple.com", "test", "A", master,)
    assert result is True


@patch("bind_manager.checker.dns.zone.from_xfr")
@patch("bind_manager.checker.dns.query.xfr")
@patch("bind_manager.checker.dns.tsigkeyring.from_text")
def test_record_existence_not_found(mock_key, mock_xfr, mock_zone):
    fake_zone = MagicMock()
    fake_zone.nodes.items.return_value = []
    mock_zone.return_value = fake_zone

    test_location = settings.locations_ip["test"]
    master = test_location["master"]

    result = checker.record_existence("apple.com", "missing", "A",  master,)
    assert result is False


@patch("bind_manager.checker.dns.resolver.Resolver")
def test_check_the_value_match(mock_resolver):
    instance = mock_resolver.return_value
    instance.resolve.return_value = ["1.2.3.4"]

    result = checker.check_the_value("apple.com", "test", "A", "1.2.3.4", "10.60.110.227")
    assert result is True


@patch("bind_manager.checker.dns.resolver.Resolver")
def test_check_the_value_mismatch(mock_resolver):
    instance = mock_resolver.return_value
    instance.resolve.return_value = ["9.9.9.9"]

    test_location = settings.locations_ip["test"]
    master = test_location["master"]


    with pytest.raises(HTTPException) as e:
        checker.check_the_value("apple.com", "test", "A", "1.2.3.4", master)
    assert e.value.status_code == 409
    assert "Record value does not match" in str(e.value.detail)
