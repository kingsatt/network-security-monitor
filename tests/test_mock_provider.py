from nsm.vulnerabilities.mock_provider import MockProvider


def test_mock_provider_returns_vulnerability():
    provider = MockProvider()

    vulnerabilities = provider.find_vulnerabilities(
        product="OpenSSH",
        version="9.9",
    )

    assert len(vulnerabilities) == 1

    assert vulnerabilities[0].cve_id == "CVE-2025-1234"


def test_mock_provider_returns_empty_list():
    provider = MockProvider()

    vulnerabilities = provider.find_vulnerabilities(
        product="Unknown",
        version="1.0",
    )

    assert vulnerabilities == []