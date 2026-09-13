from nsm.services.service_detector import ServiceDetector
from unittest.mock import patch


def test_detect_ssh():
    assert ServiceDetector.detect(22) == "SSH"


def test_detect_https():
    assert ServiceDetector.detect(443) == "HTTPS"


def test_detect_unknown_service():
    assert ServiceDetector.detect(9999) is None

def test_grab_banner_returns_decoded_banner():
    banner = b"SSH-2.0-OpenSSH_9.9\r\n"

    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.__enter__.return_value.recv.return_value = banner

        result = ServiceDetector.grab_banner(
            "127.0.0.1",
            22,
        )

    assert result == "SSH-2.0-OpenSSH_9.9"

def test_grab_banner_returns_none_when_connection_fails():
    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.__enter__.return_value.connect.side_effect = (
            ConnectionRefusedError
        )

        result = ServiceDetector.grab_banner(
            "127.0.0.1",
            22,
        )

    assert result is None