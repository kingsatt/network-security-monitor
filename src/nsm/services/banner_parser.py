import re
from dataclasses import dataclass


@dataclass
class ParsedBanner:
    product: str
    version: str | None

class BannerParser:

    @staticmethod
    def parse(banner: str) -> ParsedBanner | None:
        if not banner:
            return None

        # OpenSSH
        match = re.search(
            r"OpenSSH[_ ](?P<version>\d+(?:\.\d+)+(?:p\d+)?)",
            banner,
        )

        if match:
            return ParsedBanner(
                product="OpenSSH",
                version=match.group("version"),
            )

        # HTTP Server header
        match = re.search(
            r"Server:\s*(?P<product>[\w.-]+)(?:/(?P<version>[\d.]+))?",
            banner,
            re.IGNORECASE,
        )

        if match:
            return ParsedBanner(
                product=match.group("product"),
                version=match.group("version"),
            )

        # vsFTPd
        match = re.search(
            r"vsFTPd\s+(?P<version>[\d.]+)",
            banner,
            re.IGNORECASE,
        )

        if match:
            return ParsedBanner(
                product="vsFTPd",
                version=match.group("version"),
            )

        return None
