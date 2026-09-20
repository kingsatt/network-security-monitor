from nsm.vulnerabilities.nvd_provider import NVDProvider
from unittest.mock import patch

import httpx


def test_extract_cvss_v31():
    metrics = {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 8.8,
                    "baseSeverity": "HIGH",
                }
            }
        ]
    }

    result = NVDProvider._extract_cvss(metrics)

    assert result == (8.8, "HIGH")


def test_extract_cvss_v2_fallback():
    metrics = {
        "cvssMetricV2": [
            {
                "cvssData": {
                    "baseScore": 5.0,
                },
                "baseSeverity": "MEDIUM",
            }
        ]
    }

    result = NVDProvider._extract_cvss(metrics)

    assert result == (5.0, "MEDIUM")


def test_extract_cvss_missing():
    metrics = {}

    result = NVDProvider._extract_cvss(metrics)

    assert result is None

def test_extract_english_description():
    cve = {
        "descriptions": [
            {
                "lang": "en",
                "value": "English vulnerability description.",
            },
            {
                "lang": "es",
                "value": "Spanish vulnerability description.",
            },
        ]
    }

    result = NVDProvider._extract_description(cve)

    assert result == "English vulnerability description."


def test_extract_description_missing():
    cve = {
        "descriptions": []
    }

    result = NVDProvider._extract_description(cve)

    assert result == ""


def test_version_in_range_inclusive():
    assert NVDProvider._version_in_range(
        "9.9",
        start="6.9",
        end="10.0",
    )


def test_version_in_range_exclusive_end():
    assert not NVDProvider._version_in_range(
        "10.0",
        end="10.0",
        end_inclusive=False,
    )


def test_version_in_range_above_end():
    assert not NVDProvider._version_in_range(
        "9.9",
        end="9.8",
    )

def test_parse_cpe():
    cpe = "cpe:2.3:a:openbsd:openssh:9.9:p1:*:*:*:*:*:*"

    assert NVDProvider._parse_cpe(cpe) == (
        "openbsd",
        "openssh",
        "9.9",
    )


def test_parse_cpe_invalid():
    assert NVDProvider._parse_cpe("invalid-cpe") is None

def test_cpe_matches_exact_version():
    cpe = "cpe:2.3:a:openbsd:openssh:9.9:p1:*:*:*:*:*:*"

    assert NVDProvider._cpe_matches_version(
        cpe,
        "9.9",
    )

    assert not NVDProvider._cpe_matches_version(
        cpe,
        "9.8",
    )


def test_cpe_matches_version_range():
    cpe = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"

    assert NVDProvider._cpe_matches_version(
        cpe,
        "9.0",
        version_start_including="6.9",
        version_end_including="9.8",
    )

    assert not NVDProvider._cpe_matches_version(
        cpe,
        "9.9",
        version_start_including="6.9",
        version_end_including="9.8",
    )


def test_cpe_matches_exclusive_end():
    cpe = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"

    assert NVDProvider._cpe_matches_version(
        cpe,
        "9.9",
        version_end_excluding="10.0",
    )

    assert not NVDProvider._cpe_matches_version(
        cpe,
        "10.0",
        version_end_excluding="10.0",
    )

def test_matches_cve_configuration():
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    "cpe:2.3:a:openbsd:openssh:*:"
                                    "*:*:*:*:*:*:*"
                                ),
                                "versionStartIncluding": "6.9",
                                "versionEndIncluding": "9.8",
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert NVDProvider._matches_cve_configuration(
        cve,
        "openssh",
        "9.0",
    )

    assert not NVDProvider._matches_cve_configuration(
        cve,
        "openssh",
        "9.9",
    )

def test_matches_cve_configuration_ignores_non_vulnerable_cpe():
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": False,
                                "criteria": (
                                    "cpe:2.3:a:openbsd:openssh:9.9:"
                                    "p1:*:*:*:*:*:*"
                                ),
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert not NVDProvider._matches_cve_configuration(
        cve,
        "openssh",
        "9.9",
    )

def test_matches_cve_configuration_ignores_other_product():
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    "cpe:2.3:a:netapp:some-product:*:"
                                    "*:*:*:*:*:*:*"
                                ),
                                "versionStartIncluding": "1.0",
                                "versionEndIncluding": "10.0",
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert not NVDProvider._matches_cve_configuration(
        cve,
        "openssh",
        "9.9",
    )

def test_parse_vulnerability():
    cve = {
        "id": "CVE-2025-1234",
        "descriptions": [
            {
                "lang": "en",
                "value": "Example vulnerability",
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 8.8,
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    "cpe:2.3:a:openbsd:openssh:*:"
                                    "*:*:*:*:*:*:*"
                                ),
                                "versionStartIncluding": "9.0",
                                "versionEndIncluding": "9.9",
                            }
                        ]
                    }
                ]
            }
        ],
    }

    vulnerability = NVDProvider._parse_vulnerability(
        cve,
        "openssh",
        "9.9",
    )

    assert vulnerability is not None
    assert vulnerability.cve_id == "CVE-2025-1234"
    assert vulnerability.product == "openssh"
    assert vulnerability.version == "9.9"
    assert vulnerability.severity == "HIGH"
    assert vulnerability.cvss_score == 8.8
    assert vulnerability.description == "Example vulnerability"

def test_parse_vulnerability_version_mismatch():
    cve = {
        "id": "CVE-2025-1234",
        "descriptions": [
            {
                "lang": "en",
                "value": "Example vulnerability",
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 8.8,
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    "cpe:2.3:a:openbsd:openssh:*:"
                                    "*:*:*:*:*:*:*"
                                ),
                                "versionStartIncluding": "9.0",
                                "versionEndIncluding": "9.8",
                            }
                        ]
                    }
                ]
            }
        ],
    }

    assert NVDProvider._parse_vulnerability(
        cve,
        "openssh",
        "9.9",
    ) is None

def test_build_cpe():
    assert NVDProvider._build_cpe(
        "OpenSSH",
        "9.9",
    ) == "cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*"

def test_build_cpe_unsupported_product():
    try:
        NVDProvider._build_cpe("unknown-product", "1.0")
    except ValueError as exc:
        assert "Unsupported product" in str(exc)
    else:
        assert False

def test_find_vulnerabilities_handles_http_error():
    provider = NVDProvider()

    with patch(
        "nsm.vulnerabilities.nvd_provider.httpx.get",
        side_effect=httpx.HTTPError("NVD unavailable"),
    ):
        vulnerabilities = provider.find_vulnerabilities(
            "OpenSSH",
            "9.9",
        )

    assert vulnerabilities == []

def test_find_vulnerabilities_logs_http_error(caplog):
    provider = NVDProvider()

    with patch(
        "nsm.vulnerabilities.nvd_provider.httpx.get",
        side_effect=httpx.HTTPError("NVD unavailable"),
    ):
        with caplog.at_level("WARNING"):
            vulnerabilities = provider.find_vulnerabilities(
                "OpenSSH",
                "9.9",
            )

    assert vulnerabilities == []
    assert "NVD lookup failed for OpenSSH 9.9" in caplog.text

def test_build_mysql_cpe():
    assert NVDProvider._build_cpe(
        "MySQL",
        "8.0.36",
    ) == "cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*"

def test_build_mysql_cpe():
    assert NVDProvider._build_cpe(
        "MySQL",
        "8.0.36",
    ) == "cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*"


def test_build_postgresql_cpe():
    assert NVDProvider._build_cpe(
        "PostgreSQL",
        "16.3",
    ) == "cpe:2.3:a:postgresql:postgresql:16.3:*:*:*:*:*:*:*"


def test_build_redis_cpe():
    assert NVDProvider._build_cpe(
        "Redis",
        "7.2.5",
    ) == "cpe:2.3:a:redis:redis:7.2.5:*:*:*:*:*:*:*"


def test_build_mongodb_cpe():
    assert NVDProvider._build_cpe(
        "MongoDB",
        "7.0.12",
    ) == "cpe:2.3:a:mongodb:mongodb:7.0.12:*:*:*:*:*:*:*"

def test_version_in_range_inclusive():
    provider = NVDProvider()

    assert provider._version_in_range(
        version="7.2.5",
        start="7.2.0",
        start_inclusive=True,
        end="7.2.10",
        end_inclusive=True,
    )


def test_version_outside_range():
    provider = NVDProvider()

    assert not provider._version_in_range(
        version="7.3.0",
        start="7.2.0",
        start_inclusive=True,
        end="7.2.10",
        end_inclusive=True,
    )


def test_version_exclusive_upper_boundary():
    provider = NVDProvider()

    assert not provider._version_in_range(
        version="7.2.10",
        start="7.2.0",
        start_inclusive=True,
        end="7.2.10",
        end_inclusive=False,
    )


def test_version_exclusive_lower_boundary():
    provider = NVDProvider()

    assert not provider._version_in_range(
        version="7.2.0",
        start="7.2.0",
        start_inclusive=False,
        end="7.2.10",
        end_inclusive=True,
    )


def test_version_inside_exclusive_range():
    provider = NVDProvider()

    assert provider._version_in_range(
        version="7.2.5",
        start="7.2.0",
        start_inclusive=False,
        end="7.2.10",
        end_inclusive=False,
    )


def test_version_in_range_without_lower_bound():
    provider = NVDProvider()

    assert provider._version_in_range(
        version="7.2.5",
        start=None,
        start_inclusive=True,
        end="7.2.10",
        end_inclusive=True,
    )


def test_version_in_range_without_upper_bound():
    provider = NVDProvider()

    assert provider._version_in_range(
        version="7.2.5",
        start="7.2.0",
        start_inclusive=True,
        end=None,
        end_inclusive=True,
    )

def test_matches_cve_configuration_exact_version():
    provider = NVDProvider()

    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    "cpe:2.3:a:openbsd:openssh:9.9:"
                                    "*:*:*:*:*:*:*"
                                ),
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert provider._matches_cve_configuration(
        cve,
        product="OpenSSH",
        version="9.9",
    )


def test_matches_cve_configuration_wrong_version():
    provider = NVDProvider()

    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    "cpe:2.3:a:openbsd:openssh:9.9:"
                                    "*:*:*:*:*:*:*"
                                ),
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert not provider._matches_cve_configuration(
        cve,
        product="OpenSSH",
        version="9.8",
    )


def test_matches_cve_configuration_wrong_product():
    provider = NVDProvider()

    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    "cpe:2.3:a:openbsd:openssh:9.9:"
                                    "*:*:*:*:*:*:*"
                                ),
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert not provider._matches_cve_configuration(
        cve,
        product="MySQL",
        version="9.9",
    )


def test_matches_cve_configuration_vulnerable_false():
    provider = NVDProvider()

    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": False,
                                "criteria": (
                                    "cpe:2.3:a:openbsd:openssh:9.9:"
                                    "*:*:*:*:*:*:*"
                                ),
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert not provider._matches_cve_configuration(
        cve,
        product="OpenSSH",
        version="9.9",
    )


def test_matches_cve_configuration_version_range():
    provider = NVDProvider()

    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    "cpe:2.3:a:openbsd:openssh:"
                                    "*:*:*:*:*:*:*:*:*"
                                ),
                                "versionStartIncluding": "9.0",
                                "versionEndExcluding": "10.0",
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert provider._matches_cve_configuration(
        cve,
        product="OpenSSH",
        version="9.9",
    )

    assert not provider._matches_cve_configuration(
        cve,
        product="OpenSSH",
        version="10.0",
    )

def test_version_in_range_supports_openssh_patch_version():
    assert NVDProvider._version_in_range(
        "9.6p1",
        start="9.6",
        end="9.6p2",
    )