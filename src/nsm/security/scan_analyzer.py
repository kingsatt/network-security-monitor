from nsm.security.finding_analyzer import FindingAnalyzer


def analyze_scan(results):
    analyzer = FindingAnalyzer()

    findings = []

    for result in results:
        finding = analyzer.analyze(result)

        if finding is not None:
            findings.append(finding)

    return findings