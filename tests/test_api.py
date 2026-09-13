from unittest.mock import patch

from nsm.scanner.tcp_scanner import PortScanResult


def test_root(client):
    response = client.get("/")

    assert response.status_code == 200

    assert response.json() == {
        "message": "Network Security Monitor API is running"
    }


@patch("nsm.api.routes.run_scan")
def test_create_scan(mock_run_scan, client):
    mock_run_scan.return_value = [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            banner="SSH-2.0-Test",
        ),
        PortScanResult(
            port=80,
            is_open=False,
            service=None,
            banner=None,
        ),
    ]

    response = client.post(
        "/scan",
        json={
            "target": "127.0.0.1",
            "ports": [22, 80],
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["target"] == "127.0.0.1"
    assert len(data["results"]) == 2

    assert data["results"][0]["port"] == 22
    assert data["results"][0]["is_open"] is True
    assert data["results"][0]["service"] == "SSH"

    assert data["results"][1]["port"] == 80
    assert data["results"][1]["is_open"] is False

    mock_run_scan.assert_called_once_with(
        target="127.0.0.1",
        ports=[22, 80],
    )

def test_list_scans(client):
    response = client.get("/scans")

    assert response.status_code == 200
    assert response.json() == []


def test_list_scans_after_scan(client):
    response = client.post(
        "/scan",
        json={
            "target": "127.0.0.1",
            "ports": [22],
        },
    )

    assert response.status_code == 200

    response = client.get("/scans")

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == 1
    assert data[0]["target"] == "127.0.0.1"
    assert data[0]["completed_at"] is not None