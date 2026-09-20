from nsm.vulnerabilities.models import Vulnerability
from nsm.vulnerabilities.provider import VulnerabilityProvider


class VulnerabilityScanner:

    def __init__(
        self,
        provider: VulnerabilityProvider,
    ):
        self.provider = provider

    def scan(
        self,
        product: str | None,
        version: str | None,
    ) -> list[Vulnerability]:

        if product is None:
            return []

        if version is None:
            return []

        return self.provider.find_vulnerabilities(
            product=product,
            version=version,
        )