import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from main import app


client = TestClient(app)


@pytest.fixture
def mock_settings(monkeypatch):
    """Mock entire settings object instead of single attribute"""
    mock_settings_obj = MagicMock()
    mock_settings_obj.locations_ip = {
        "tehran": {
            "master": "10.60.110.227",
            "forwarder_1": "10.60.110.229",
            "forwarder_2": "10.60.110.230"
        }
    }

    # Replace the whole settings object in main
    #monkeypatch.setattr("main.settings", mock_settings_obj)
    monkeypatch.setattr("config.settings", mock_settings_obj)

    return mock_settings_obj

@pytest.fixture
def record_detail():
    return {
        "zone": "apple.com",
        "record_name": "test",
        "record_value": "1.2.3.4",
        "ttl": 300,
        "priority": 10,
        "location": "test",
        "second_value": "1.2.3.5"
    }


@patch("main.authenticate_user")
@patch("main.record_manager.add_record")
def test_add_record(mock_add_record, mock_auth, mock_settings, record_detail):
    mock_auth.return_value = None
    mock_add_record.return_value = None

    response = client.post(
        "/add/A/",
        json=record_detail,
        headers={"token": "fake-token"}
    )

    assert response.status_code == 200
    assert "موفقیت" in response.json()["message"]

    mock_auth.assert_called_once()
    mock_add_record.assert_called_once_with(
        "apple.com", "test", "A", "1.2.3.4", 300, 10,
        "10.60.110.227", "10.60.110.229", "10.60.110.230"
    )


@patch("main.authenticate_user")
@patch("main.record_manager.del_record")
def test_delete_record(mock_del_record, mock_auth, mock_settings, record_detail):
    mock_auth.return_value = None
    mock_del_record.return_value = None

    response = client.post(
        "/delete/A/",
        json=record_detail,
        headers={"token": "fake-token"}
    )

    assert response.status_code == 200
    assert "با موفقیت حذف" in response.json()["message"]

    mock_auth.assert_called_once()
    mock_del_record.assert_called_once()


@patch("main.authenticate_user")
@patch("main.record_manager.update_record_progress")
def test_update_record(mock_update, mock_auth, mock_settings, record_detail):
    mock_auth.return_value = None
    mock_update.return_value = {"status": "ok"}

    response = client.post(
        "/update/A/",
        json=record_detail,
        headers={"token": "fake-token"}
    )

    assert response.status_code == 200
    assert "با موفقیت تغییر" in response.json()["message"]

    mock_auth.assert_called_once()
    mock_update.assert_called_once_with(
        "apple.com", "test", "A", "1.2.3.4", "1.2.3.5", 300, 10,
        "10.60.110.227", "10.60.110.229", "10.60.110.230"
    )


def test_invalid_location_raises(mock_settings, record_detail):
    """Location not in settings.locations_ip should raise 403"""
    record_detail["location"] = "unknown"

    response = client.post(
        "/add/A/",
        json=record_detail,
        headers={"token": "fake-token"}
    )

    assert response.status_code == 403
    assert "لوکیشن وجود ندارد" in response.json()["detail"]["error"]
