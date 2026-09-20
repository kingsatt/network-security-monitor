from nsm.security.risk_analyzer import RiskAnalyzer
from nsm.vulnerabilities.models import Vulnerability


def make_vulnerability(cvss_score: float) -> Vulnerability:
    return Vulnerability(
        cve_id="CVE-2025-1234",
        product="OpenSSH",
        version="9.9",
        severity="HIGH",
        cvss_score=cvss_score,
        description="Test vulnerability",
    )


def test_critical_risk():
    vulnerability = make_vulnerability(9.0)

    result = RiskAnalyzer.assess(
        vulnerability=vulnerability,
        exposed=True,
    )

    assert result.risk_level == "CRITICAL"
    assert result.risk_score == 10.0
    assert "exposed" in result.reason

def test_high_risk():
    vulnerability = make_vulnerability(7.5)

    result = RiskAnalyzer.assess(
        vulnerability=vulnerability,
        exposed=True,
    )

    assert result.risk_level == "HIGH"


def test_medium_risk():
    vulnerability = make_vulnerability(5.0)

    result = RiskAnalyzer.assess(
        vulnerability=vulnerability,
        exposed=True,
    )

    assert result.risk_level == "MEDIUM"


def test_low_risk():
    vulnerability = make_vulnerability(3.9)

    result = RiskAnalyzer.assess(
        vulnerability=vulnerability,
        exposed=True,
    )

    assert result.risk_level == "MEDIUM"
    assert result.risk_score == 4.9


def test_unexposed_vulnerability_reason():
    vulnerability = make_vulnerability(7.5)

    result = RiskAnalyzer.assess(
        vulnerability=vulnerability,
        exposed=False,
    )

    assert result.risk_level == "HIGH"
    assert "not exposed" in result.reason

def test_exposed_vulnerability_increases_risk_score():
    vulnerability = make_vulnerability(6.5)

    result = RiskAnalyzer.assess(
        vulnerability=vulnerability,
        exposed=True,
    )

    assert result.risk_score == 7.5
    assert result.risk_level == "HIGH"


def test_unexposed_vulnerability_keeps_cvss_score():
    vulnerability = make_vulnerability(6.5)

    result = RiskAnalyzer.assess(
        vulnerability=vulnerability,
        exposed=False,
    )

    assert result.risk_score == 6.5
    assert result.risk_level == "MEDIUM"


def test_risk_score_cannot_exceed_ten():
    vulnerability = make_vulnerability(9.8)

    result = RiskAnalyzer.assess(
        vulnerability=vulnerability,
        exposed=True,
    )

    assert result.risk_score == 10.0