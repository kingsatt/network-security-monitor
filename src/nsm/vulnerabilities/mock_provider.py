from nsm.vulnerabilities.models import Vulnerability
from nsm.vulnerabilities.provider import VulnerabilityProvider


class MockProvider(VulnerabilityProvider):

    def find_vulnerabilities(
        self,
        product: str,
        version: str,
    ) -> list[Vulnerability]:

        if (
            product == "OpenSSH"
            and version == "9.9"
        ):
            return [
                Vulnerability(
                    cve_id="CVE-2025-1234",
                    product=product,
                    version=version,
                    severity="HIGH",
                    cvss_score=8.8,
                    description="Example OpenSSH vulnerability",
                )
            ]

        return []