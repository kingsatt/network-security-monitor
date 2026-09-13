import logging
import socket
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from nsm.services.service_detector import ServiceDetector

logger = logging.getLogger(__name__)



@dataclass
class PortScanResult:
    port: int
    is_open: bool
    service: Optional[str] = None
    banner: Optional[str] = None


class TCPScanner:
    def __init__(self, target: str):
        self.target = target

    @staticmethod
    def _validate_port(port: int) -> None:
        if not isinstance(port, int):
            raise TypeError("port must be an integer")

        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")

    def scan_port(self, port: int) -> bool:
        self._validate_port(port)

        logger.info("Scanning %s:%d", self.target, port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)

        try:
            sock.connect((self.target, port))

            logger.info("Port %d is open", port)

            return True

        except ConnectionRefusedError:
            logger.info("Port %d is closed", port)
            return False

        except TimeoutError:
            logger.warning("Connection to %s:%d timed out", self.target, port)
            return False

        except OSError as exc:
            logger.error(
                "Socket error while scanning %s:%d: %s",
                self.target,
                port,
                exc,
            )
            return False

        finally:
            sock.close()

    def scan_ports(self, ports: list[int]) -> list[PortScanResult]:
        results = []

        for port in ports:
            is_open = self.scan_port(port)

            service = None
            banner = None

            if is_open:
                service = ServiceDetector.detect(port)
                banner = ServiceDetector.grab_banner(
                    self.target,
                    port,
                )

            results.append(
                PortScanResult(
                    port=port,
                    is_open=is_open,
                    service=service,
                    banner=banner,
                )
            )

        return results

    def scan_ports_concurrent(
        self,
        ports: list[int],
        max_workers: int = 10,
    ) -> list[PortScanResult]:

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            open_statuses = list(
                executor.map(self.scan_port, ports)
            )

        return [
            PortScanResult(
                port=port,
                is_open=is_open,
                service=ServiceDetector.detect(port)
                if is_open
                else None,
                banner=ServiceDetector.grab_banner(
                    self.target,
                    port,
                )
                if is_open
                else None,
            )
            for port, is_open in zip(ports, open_statuses)
        ]