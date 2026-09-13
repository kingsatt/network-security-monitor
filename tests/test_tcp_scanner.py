import pytest
from unittest.mock import patch

from nsm.scanner.tcp_scanner import TCPScanner, PortScanResult
from nsm.services.service_detector import ServiceDetector
from nsm.services.banner_parser import BannerParser, ParsedBanner


def test_scan_port_returns_true_when_connection_succeeds():
    scanner = TCPScanner("127.0.0.1")

    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.connect.return_value = None

        result = scanner.scan_port(22)

    assert result is True


def test_scan_port_returns_false_when_connection_is_refused():
    scanner = TCPScanner("127.0.0.1")

    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.connect.side_effect = ConnectionRefusedError

        result = scanner.scan_port(22)

    assert result is False


def test_scan_port_returns_false_when_connection_times_out():
    scanner = TCPScanner("127.0.0.1")

    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.connect.side_effect = TimeoutError

        result = scanner.scan_port(22)

    assert result is False


def test_scan_port_returns_false_when_socket_error_occurs():
    scanner = TCPScanner("127.0.0.1")

    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.connect.side_effect = OSError

        result = scanner.scan_port(22)

    assert result is False

def test_scan_ports_returns_results_for_each_port():
    scanner = TCPScanner("127.0.0.1")

    with patch.object(scanner, "scan_port") as mock_scan_port, \
         patch.object(ServiceDetector, "grab_banner") as mock_grab_banner:

        mock_scan_port.side_effect = [True, False, True]
        mock_grab_banner.return_value = None

        results = scanner.scan_ports([22, 80, 443])

    assert results == [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            banner=None,
        ),
        PortScanResult(
            port=80,
            is_open=False,
            service=None,
            banner=None,
        ),
        PortScanResult(
            port=443,
            is_open=True,
            service="HTTPS",
            banner=None,
        ),
    ]

def test_scan_ports_scans_each_port():
    scanner = TCPScanner("127.0.0.1")

    with patch.object(scanner, "scan_port", return_value=True) as mock_scan_port:
        scanner.scan_ports([22, 80, 443])

    assert mock_scan_port.call_count == 3
    mock_scan_port.assert_any_call(22)
    mock_scan_port.assert_any_call(80)
    mock_scan_port.assert_any_call(443)

def test_scan_port_rejects_port_zero():
    scanner = TCPScanner("127.0.0.1")

    with pytest.raises(ValueError, match="between 1 and 65535"):
        scanner.scan_port(0)

def test_scan_port_rejects_negative_port():
    scanner = TCPScanner("127.0.0.1")

    with pytest.raises(ValueError, match="between 1 and 65535"):
        scanner.scan_port(-1)

def test_scan_port_rejects_non_integer_port():
    scanner = TCPScanner("127.0.0.1")

    with pytest.raises(TypeError, match="port must be an integer"):
        scanner.scan_port("22")

def test_scan_port_logs_open_port(caplog):
    scanner = TCPScanner("127.0.0.1")

    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.connect.return_value = None

        with caplog.at_level("INFO"):
            result = scanner.scan_port(22)

    assert result is True
    assert "Port 22 is open" in caplog.text


def test_scan_port_logs_closed_port(caplog):
    scanner = TCPScanner("127.0.0.1")

    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.connect.side_effect = ConnectionRefusedError

        with caplog.at_level("INFO"):
            result = scanner.scan_port(22)

    assert result is False
    assert "Port 22 is closed" in caplog.text

def test_scan_ports_concurrent_returns_results():
    scanner = TCPScanner("127.0.0.1")

    def scan_port_side_effect(port):
        return port in (22, 443)

    with patch.object(
        scanner,
        "scan_port",
        side_effect=scan_port_side_effect,
    ), patch.object(
        ServiceDetector,
        "grab_banner",
        return_value=None,
    ):
        results = scanner.scan_ports_concurrent(
            [22, 80, 443]
        )

    assert results == [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            banner=None,
        ),
        PortScanResult(
            port=80,
            is_open=False,
            service=None,
            banner=None,
        ),
        PortScanResult(
            port=443,
            is_open=True,
            service="HTTPS",
            banner=None,
        ),
    ]

def test_scan_ports_concurrent_scans_each_port():
    scanner = TCPScanner("127.0.0.1")

    with patch.object(
        scanner,
        "scan_port",
        return_value=True,
    ) as mock_scan_port:

        scanner.scan_ports_concurrent(
            [22, 80, 443]
        )

    assert mock_scan_port.call_count == 3

    mock_scan_port.assert_any_call(22)
    mock_scan_port.assert_any_call(80)
    mock_scan_port.assert_any_call(443)

def test_scan_ports_includes_banner_for_open_port():
    scanner = TCPScanner("127.0.0.1")

    with patch.object(
        scanner,
        "scan_port",
        return_value=True,
    ), patch.object(
        ServiceDetector,
        "grab_banner",
        return_value="SSH-2.0-OpenSSH_9.9",
    ) as mock_grab_banner:

        results = scanner.scan_ports([22])

    assert results == [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            banner="SSH-2.0-OpenSSH_9.9",
            product="OpenSSH",
            version="9.9",
        )
    ]

    mock_grab_banner.assert_called_once_with(
        "127.0.0.1",
        22,
    )

def test_scan_ports_parses_banner():
    scanner = TCPScanner("127.0.0.1")

    with patch.object(scanner, "scan_port", return_value=True), \
         patch.object(
             ServiceDetector,
             "grab_banner",
             return_value="SSH-2.0-OpenSSH_9.9",
         ), \
         patch.object(
             BannerParser,
             "parse",
             return_value=ParsedBanner(
                 product="OpenSSH",
                 version="9.9",
             ),
         ) as mock_parse:

        results = scanner.scan_ports([22])

    assert results == [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            banner="SSH-2.0-OpenSSH_9.9",
            product="OpenSSH",
            version="9.9",
        )
    ]

    mock_parse.assert_called_once_with("SSH-2.0-OpenSSH_9.9")