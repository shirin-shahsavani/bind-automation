import pytest
from fastapi import HTTPException
from unittest.mock import patch, MagicMock
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# فایل اصلی که داریم تست می‌کنیم
from bind_manager import record_manager


@pytest.fixture
def mock_checker(monkeypatch):
    """Mock the checker module used in record_manager."""
    mock_checker = MagicMock()
    monkeypatch.setattr("bind_manager.record_manager.checker", mock_checker)
    return mock_checker


@pytest.fixture
def mock_dns(monkeypatch):
    """Mock DNS query and update functions."""
    monkeypatch.setattr("dns.query.tcp", MagicMock(return_value=MagicMock(rcode=lambda: 0)))
    monkeypatch.setattr("dns.rcode.NOERROR", 0)
    monkeypatch.setattr("dns.rcode.to_text", lambda x: "NOERROR")
    monkeypatch.setattr("bind_manager.record_manager.run_apply", MagicMock())
    monkeypatch.setattr("bind_manager.record_manager.verify_forwarder_after_record_add", MagicMock())
    return


def test_add_record_success(mock_checker, mock_dns):
    """✅ Test that add_record calls add_record_by_type when record does not exist."""
    mock_checker.record_existance.return_value = False
    mock_add_by_type = MagicMock()
    with patch("bind_manager.record_manager.add_record_by_type", mock_add_by_type):
        record_manager.add_record(
            zone="example.com",
            new_record="www",
            new_record_type="A",
            new_record_value="192.168.1.10",
            ttl=300,
            priority=None,
            location_ip_master="10.60.110.227",
            location_ip_forwarder_1="10.60.110.228",
            location_ip_forwarder_2="10.60.110.229",
        )

    mock_checker.check_record_type.assert_called_once_with("A")
    mock_checker.zone_existance.assert_called_once_with("example.com", "10.60.110.227")
    mock_add_by_type.assert_called_once()


def test_add_record_exists(mock_checker):
    """🚫 Test that add_record raises HTTPException when record already exists."""
    mock_checker.record_existance.return_value = True

    with pytest.raises(HTTPException) as exc_info:
        record_manager.add_record(
            zone="example.com",
            new_record="www",
            new_record_type="A",
            new_record_value="192.168.1.10",
            ttl=300,
            priority=None,
            location_ip_master="10.60.110.227",
            location_ip_forwarder_1="10.60.110.228",
            location_ip_forwarder_2="10.60.110.229",
        )

    assert exc_info.value.status_code == 404
    assert "درخواست شما با خطا مواجه شد" in str(exc_info.value.detail)


def test_add_record_by_type_calls_correct_func(monkeypatch):
    """⚙️ Ensure add_record_by_type calls correct handler function."""
    mock_add_A = MagicMock()
    monkeypatch.setattr("bind_manager.record_manager.add_A_record", mock_add_A)

    record_manager.add_record_by_type(
        zone="example.com",
        new_record="www",
        new_record_type="A",
        new_record_value="192.168.1.10",
        ttl=300,
        location_ip_master="10.60.110.227",
        location_ip_forwarder_1="10.60.110.228",
        location_ip_forwarder_2="10.60.110.229",
    )

    mock_add_A.assert_called_once()


def test_add_PTR_record_invalid_octet(monkeypatch):
    """🚫 Test PTR record fails when octet > 254."""
    mock_get_ptr = MagicMock(return_value=[])
    monkeypatch.setattr("bind_manager.record_manager.get_all_ptr_records", mock_get_ptr)

    with pytest.raises(HTTPException) as exc_info:
        record_manager.add_PTR_record(
            zone="1.168.192.in-addr.arpa",
            new_record="255",
            new_record_type="PTR",
            new_record_value="www.example.com.",
            ttl=300,
            location_ip_master="10.60.110.227",
            location_ip_forwarder_1="10.60.110.228",
            location_ip_forwarder_2="10.60.110.229",
        )

    assert "مقدار رکورد بیشتر از 254 میباشد" in str(exc_info.value.detail)


def test_get_all_ptr_records(monkeypatch):
    """📦 Test that get_all_ptr_records returns iterator on success."""
    fake_zone = MagicMock()
    fake_zone.nodes.items.return_value = []
    monkeypatch.setattr("dns.zone.from_xfr", lambda *a, **k: fake_zone)
    monkeypatch.setattr("dns.query.xfr", lambda *a, **k: "ok")

    result = record_manager.get_all_ptr_records("1.168.192.in-addr.arpa", "10.60.110.227")
    assert hasattr(result, "__iter__")


def test_get_all_ptr_records_failure(monkeypatch, caplog):
    """💥 Test that get_all_ptr_records handles exceptions and returns empty iterator."""
    monkeypatch.setattr("dns.query.xfr", lambda *a, **k: (_ for _ in ()).throw(Exception("xfr fail")))
    result = record_manager.get_all_ptr_records("zone", "10.60.110.227")
    assert list(result) == []
    assert "Zone transfer failed" in caplog.text
