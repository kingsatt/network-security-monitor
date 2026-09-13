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

@patch("nsm.api.routes.run_scan")
def test_create_scan_returns_security_findings(mock_run_scan, client):
    mock_run_scan.return_value = [
        PortScanResult(
            port=23,
            is_open=True,
            service="TELNET",
            banner="Telnet test banner",
        ),
    ]

    response = client.post(
        "/scan",
        json={
            "target": "127.0.0.1",
            "ports": [23],
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["findings"]) == 1

    finding = data["findings"][0]

    assert finding["rule_id"] == "TELNET_EXPOSED"
    assert finding["port"] == 23
    assert finding["service"] == "TELNET"
    assert finding["severity"] == "HIGH"
    assert finding["title"] == "Insecure Telnet service exposed"
    assert finding["recommendation"] == (
        "Disable Telnet and use SSH for secure remote administration."
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

def test_scan_rejects_empty_ports(client):
    response = client.post(
        "/scan",
        json={
            "target": "127.0.0.1",
            "ports": [],
        },
    )

    assert response.status_code == 422


def test_scan_rejects_invalid_port(client):
    response = client.post(
        "/scan",
        json={
            "target": "127.0.0.1",
            "ports": [0],
        },
    )

    assert response.status_code == 422


def test_scan_rejects_port_above_maximum(client):
    response = client.post(
        "/scan",
        json={
            "target": "127.0.0.1",
            "ports": [65536],
        },
    )

    assert response.status_code == 422

def test_scan_rejects_empty_target(client):
    response = client.post(
        "/scan",
        json={
            "target": "",
            "ports": [22],
        },
    )

    assert response.status_code == 422

def test_scan_strips_target_whitespace(client):
    response = client.post(
        "/scan",
        json={
            "target": "  127.0.0.1  ",
            "ports": [22],
        },
    )

    assert response.status_code == 200
    assert response.json()["target"] == "127.0.0.1"

def test_scan_persists_and_returns_security_findings(client):
    response = client.post(
        "/scan",
        json={
            "target": "127.0.0.1",
            "ports": [23],
        },
    )

    assert response.status_code == 200

    scan_response = response.json()

    assert "findings" in scan_response

    # Port 23 may not actually be open on the test machine,
    # so this test should mock the scanner result.

@patch("nsm.services.scan_service.perform_scan")
def test_scan_persists_results_and_findings(mock_perform_scan, client):
    mock_perform_scan.return_value = [
        PortScanResult(
            port=23,
            is_open=True,
            service="TELNET",
            banner="Telnet test banner",
        ),
    ]

    response = client.post(
        "/scan",
        json={
            "target": "127.0.0.1",
            "ports": [23],
        },
    )

    assert response.status_code == 200

    data = response.json()
    assert data["target"] == "127.0.0.1"
    assert len(data["results"]) == 1
    assert len(data["findings"]) == 1

    scan_response = client.get("/scans/1")

    assert scan_response.status_code == 200

    scan_data = scan_response.json()

    assert scan_data["id"] == 1
    assert scan_data["target"] == "127.0.0.1"

    assert len(scan_data["results"]) == 1
    assert scan_data["results"][0]["port"] == 23
    assert scan_data["results"][0]["service"] == "TELNET"

    assert len(scan_data["findings"]) == 1
    assert scan_data["findings"][0]["rule_id"] == "TELNET_EXPOSED"
    assert scan_data["findings"][0]["severity"] == "HIGH"