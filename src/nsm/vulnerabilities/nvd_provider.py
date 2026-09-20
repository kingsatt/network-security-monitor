import httpx

from nsm.vulnerabilities.models import Vulnerability
from nsm.vulnerabilities.provider import VulnerabilityProvider
from packaging.version import Version
import logging

logger = logging.getLogger(__name__)


class NVDProvider(VulnerabilityProvider):
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CPE_VENDORS = {
        "openssh": "openbsd",
        "mysql": "oracle",
        "postgresql": "postgresql",
        "redis": "redis",
        "mongodb": "mongodb",
    }

    def find_vulnerabilities(
        self,
        product: str,
        version: str,
    ) -> list[Vulnerability]:
        cpe = self._build_cpe(product, version)

        params = {
            "cpeName": cpe,
        }

        try:
            response = httpx.get(
                self.BASE_URL,
                params=params,
                timeout=10.0,
            )

            response.raise_for_status()

        except httpx.HTTPError as exc:
            logger.warning(
                "NVD lookup failed for %s %s: %s",
                product,
                version,
                exc,
            )
            return []

        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})

            vulnerability = self._parse_vulnerability(
                cve=cve,
                product=product,
                version=version,
            )

            if vulnerability is not None:
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    @staticmethod
    def _extract_cvss(metrics: dict) -> tuple[float, str] | None:
        cvss_v31 = metrics.get("cvssMetricV31")

        if cvss_v31:
            cvss_data = cvss_v31[0]["cvssData"]

            return (
                cvss_data["baseScore"],
                cvss_data["baseSeverity"],
            )

        cvss_v2 = metrics.get("cvssMetricV2")

        if cvss_v2:
            cvss_data = cvss_v2[0]["cvssData"]

            return (
                cvss_data["baseScore"],
                cvss_v2[0]["baseSeverity"],
            )

        return None

    @staticmethod
    def _extract_description(cve: dict) -> str:
        descriptions = cve.get("descriptions", [])

        for description in descriptions:
            if description.get("lang") == "en":
                return description.get("value", "")

        return ""

    @staticmethod
    def _version_in_range(
        version: str,
        start: str | None = None,
        start_inclusive: bool = True,
        end: str | None = None,
        end_inclusive: bool = True,
    ) -> bool:
        current = Version(version)

        if start is not None:
            start_version = Version(start)

            if start_inclusive:
                if current < start_version:
                    return False
            else:
                if current <= start_version:
                    return False

        if end is not None:
            end_version = Version(end)

            if end_inclusive:
                if current > end_version:
                    return False
            else:
                if current >= end_version:
                    return False

        return True

    @staticmethod
    def _parse_cpe(cpe: str) -> tuple[str, str, str] | None:
        parts = cpe.split(":")

        if len(parts) < 6:
            return None

        if parts[0] != "cpe" or parts[1] != "2.3":
            return None

        vendor = parts[3]
        product = parts[4]
        version = parts[5]

        return vendor, product, version

    @staticmethod
    def _cpe_matches_version(
        cpe: str,
        version: str,
        version_start_including: str | None = None,
        version_start_excluding: str | None = None,
        version_end_including: str | None = None,
        version_end_excluding: str | None = None,
    ) -> bool:
        parsed = NVDProvider._parse_cpe(cpe)

        if parsed is None:
            return False

        _, _, cpe_version = parsed

        if cpe_version not in ("*", "-"):
            return cpe_version == version

        if version_start_including is not None:
            if not NVDProvider._version_in_range(
                version,
                start=version_start_including,
                start_inclusive=True,
            ):
                return False

        if version_start_excluding is not None:
            if not NVDProvider._version_in_range(
                version,
                start=version_start_excluding,
                start_inclusive=False,
            ):
                return False

        if version_end_including is not None:
            if not NVDProvider._version_in_range(
                version,
                end=version_end_including,
                end_inclusive=True,
            ):
                return False

        if version_end_excluding is not None:
            if not NVDProvider._version_in_range(
                version,
                end=version_end_excluding,
                end_inclusive=False,
            ):
                return False

        return True

    @staticmethod
    def _matches_cve_configuration(
        cve: dict,
        product: str,
        version: str,
    ) -> bool:
        configurations = cve.get("configurations", [])

        for configuration in configurations:
            nodes = configuration.get("nodes", [])

            for node in nodes:
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue

                    cpe = match.get("criteria")

                    if not cpe:
                        continue

                    parsed = NVDProvider._parse_cpe(cpe)

                    if parsed is None:
                        continue

                    _, cpe_product, _ = parsed

                    if cpe_product.lower() != product.lower():
                        continue

                    if NVDProvider._cpe_matches_version(
                        cpe=cpe,
                        version=version,
                        version_start_including=match.get(
                            "versionStartIncluding"
                        ),
                        version_start_excluding=match.get(
                            "versionStartExcluding"
                        ),
                        version_end_including=match.get(
                            "versionEndIncluding"
                        ),
                        version_end_excluding=match.get(
                            "versionEndExcluding"
                        ),
                    ):
                        return True

        return False

    @staticmethod
    def _parse_vulnerability(
        cve: dict,
        product: str,
        version: str,
    ) -> Vulnerability | None:
        if not NVDProvider._matches_cve_configuration(
            cve,
            product,
            version,
        ):
            return None

        cve_id = cve.get("id")

        if not cve_id:
            return None

        metrics = cve.get("metrics", {})

        cvss = NVDProvider._extract_cvss(metrics)

        if cvss is None:
            return None

        cvss_score, severity = cvss

        description = NVDProvider._extract_description(cve)

        return Vulnerability(
            cve_id=cve_id,
            product=product,
            version=version,
            severity=severity,
            cvss_score=cvss_score,
            description=description,
        )

    @staticmethod
    def _build_cpe(product: str, version: str) -> str:
        product_name = product.lower()
        vendor = NVDProvider.CPE_VENDORS.get(product_name)

        if vendor is None:
            raise ValueError(
                f"Unsupported product for CPE lookup: {product}"
            )

        return (
            f"cpe:2.3:a:{vendor}:{product_name}:{version}"
            ":*:*:*:*:*:*:*"
        )