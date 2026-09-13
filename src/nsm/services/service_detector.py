import socket
from typing import Optional


class ServiceDetector:
    PORT_SERVICES = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MYSQL",
        5432: "POSTGRESQL",
        6379: "REDIS",
        8080: "HTTP-ALT",
        3389: "RDP",
        5900: "VNC",
        27017: "MONGODB",
    }

    @classmethod
    def detect(cls, port: int) -> Optional[str]:
        return cls.PORT_SERVICES.get(port)

    @staticmethod
    def grab_banner(
        target: str,
        port: int,
        timeout: float = 2.0,
    ) -> Optional[str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((target, port))

                if port in (80, 8080):
                    sock.sendall(
                        b"HEAD / HTTP/1.0\r\n"
                        b"Host: localhost\r\n"
                        b"\r\n"
                    )

                banner = sock.recv(1024)

                return banner.decode("utf-8", errors="replace").strip()

        except (ConnectionRefusedError, TimeoutError, OSError):
            return None