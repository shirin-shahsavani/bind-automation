import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config.settings import settings
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from main import app

client = TestClient(app)

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
def test_add_record(mock_add_record, mock_auth, record_detail):
    mock_auth.return_value = None
    mock_add_record.return_value = None

    test_location = settings.locations_ip["test"]
    master = test_location["master"]
    forwarders = test_location["forwarders"]

    response = client.post(
        "/add/A/",
        json=record_detail,
        headers={"token": "fake-token"}
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Record created successfully."

    mock_auth.assert_called_once()
    mock_add_record.assert_called_once_with(
        "apple.com",
        "test",
        "A",
        "1.2.3.4",
        300,
        10,
        master,
        forwarders,
        operation_id=mock_add_record.call_args.kwargs["operation_id"],
    )


@patch("main.authenticate_user")
@patch("main.record_manager.del_record")
def test_delete_record(mock_del_record, mock_auth, record_detail):
    mock_auth.return_value = None
    mock_del_record.return_value = None

    response = client.post(
        "/delete/A/",
        json=record_detail,
        headers={"token": "fake-token"}
    )

    assert response.status_code == 200
    assert response.json()["message"] == "The record was successfully deleted."

    mock_auth.assert_called_once()
    mock_del_record.assert_called_once()


@patch("main.authenticate_user")
@patch("main.record_manager.update_record_progress")
def test_update_record(mock_update, mock_auth, record_detail):
    mock_auth.return_value = None
    mock_update.return_value = {"status": "ok"}

    response = client.post(
        "/update/A/",
        json=record_detail,
        headers={"token": "fake-token"}
    )
    test_location = settings.locations_ip["test"]
    master = test_location["master"]
    forwarders = test_location["forwarders"]

    assert response.status_code == 200
    assert response.json()["message"] == "The record value was successfully updated."

    mock_auth.assert_called_once()
    mock_update.assert_called_once_with(
        "apple.com",
        "test",
        "A",
        "1.2.3.4",
        "1.2.3.5",
        300,
        10,
        master,
        forwarders,
        operation_id=mock_update.call_args.kwargs["operation_id"],
    )

def test_invalid_location_raises( record_detail):
    """Location not in settings.locations_ip should raise 404"""
    record_detail["location"] = "unknown"

    response = client.post(
        "/add/A/",
        json=record_detail,
        headers={"token": "fake-token"}
    )

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "This location does not exist"
