async function loadDashboard() {
    try {
        // --------------------------------
        // Load all scans
        // --------------------------------

        const scansResponse = await fetch("/scans");

        if (!scansResponse.ok) {
            throw new Error("Failed to load scans");
        }

        const scans = await scansResponse.json();

        if (scans.length === 0) {
            console.log("No scans available");
            return;
        }

        // The API returns scans newest first
        const latestScan = scans[0];

        // --------------------------------
        // Load scan data
        // --------------------------------

        const [dashboardResponse, detailResponse] = await Promise.all([
            fetch(`/scans/${latestScan.id}/dashboard`),
            fetch(`/scans/${latestScan.id}`),
        ]);

        if (!dashboardResponse.ok || !detailResponse.ok) {
            throw new Error("Failed to load scan data");
        }

        const dashboard = await dashboardResponse.json();
        const detail = await detailResponse.json();
        const openServices = detail.results.filter(
            result => result.is_open
        );

        // --------------------------------
        // Target
        // --------------------------------

        const targetElement = document.querySelector("#target");

        if (targetElement) {
            targetElement.textContent = dashboard.target;
        }

        // --------------------------------
        // Last scan
        // --------------------------------

        const scanTimeElement = document.querySelector("#scan-time");

        if (scanTimeElement && dashboard.completed_at) {
            const scanDate = new Date(dashboard.completed_at);
            scanTimeElement.textContent = scanDate.toLocaleString();
        }

        // --------------------------------
        // Open ports
        // --------------------------------

        const openPortsElement = document.querySelector("#open-ports");

        if (openPortsElement) {
            openPortsElement.textContent = dashboard.open_ports;
        }

        // --------------------------------
        // Findings count
        // --------------------------------

        const findingCountElement =
            document.querySelector("#finding-count");

        if (findingCountElement) {
            const findings = dashboard.findings;

            const findingCount =
                findings.critical +
                findings.high +
                findings.medium +
                findings.low;

            findingCountElement.textContent = findingCount;
        }

        // --------------------------------
        // Vulnerabilities count
        // --------------------------------

        const vulnerabilityCountElement =
            document.querySelector("#vulnerability-count");

        if (vulnerabilityCountElement) {
            const vulnerabilities = dashboard.vulnerabilities;

            const vulnerabilityCount =
                vulnerabilities.critical +
                vulnerabilities.high +
                vulnerabilities.medium +
                vulnerabilities.low;

            vulnerabilityCountElement.textContent = vulnerabilityCount;
        }

        // --------------------------------
        // Risk level
        // --------------------------------

        const riskLevelElement =
            document.querySelector("#risk-level");

        if (riskLevelElement) {

            const risks = dashboard.risks;

            riskLevelElement.classList.remove(
                "risk-critical",
                "risk-high",
                "risk-medium",
                "risk-low",
                "risk-none",
            );

            if (risks.critical > 0) {

                riskLevelElement.textContent = "CRITICAL";
                riskLevelElement.classList.add("risk-critical");

            } else if (risks.high > 0) {

                riskLevelElement.textContent = "HIGH";
                riskLevelElement.classList.add("risk-high");

            } else if (risks.medium > 0) {

                riskLevelElement.textContent = "MEDIUM";
                riskLevelElement.classList.add("risk-medium");

            } else if (risks.low > 0) {

                riskLevelElement.textContent = "LOW";
                riskLevelElement.classList.add("risk-low");

            } else {

                riskLevelElement.textContent = "NONE";
                riskLevelElement.classList.add("risk-none");
            }
        }

        if (riskLevelElement) {
            const risks = dashboard.risks;

            if (risks.critical > 0) {
                riskLevelElement.textContent = "CRITICAL";
            } else if (risks.high > 0) {
                riskLevelElement.textContent = "HIGH";
            } else if (risks.medium > 0) {
                riskLevelElement.textContent = "MEDIUM";
            } else if (risks.low > 0) {
                riskLevelElement.textContent = "LOW";
            } else {
                riskLevelElement.textContent = "NONE";
            }
        }

        // --------------------------------
        // Security Overview
        // --------------------------------

        const findings = dashboard.findings;

        const totalFindings =
            findings.critical +
            findings.high +
            findings.medium +
            findings.low;

        const severityLevels = [
            "critical",
            "high",
            "medium",
            "low",
        ];

        severityLevels.forEach((severity) => {
            const count = findings[severity];

            const countElement =
                document.querySelector(`#${severity}-count`);

            const barElement =
                document.querySelector(`#${severity}-bar`);

            if (countElement) {
                countElement.textContent = count;
            }

            if (barElement) {
                const percentage =
                    totalFindings > 0
                        ? (count / totalFindings) * 100
                        : 0;

                barElement.style.width = `${percentage}%`;
            }
        });

        // --------------------------------
        // Risk Distribution
        // --------------------------------

        const risks = dashboard.risks;

        const riskLevels = [
            "critical",
            "high",
            "medium",
            "low",
        ];

        riskLevels.forEach((risk) => {
            const count = risks[risk];

            const element =
                document.querySelector(`#risk-${risk}`);

            if (element) {
                element.textContent = count;
            }
        });

        // --------------------------------
        // Open Services
        // --------------------------------

        const servicesTable =
            document.querySelector("#services-table");

        const portCountElement =
            document.querySelector("#port-count");

        const openResults = detail.results.filter(
            (result) => result.is_open
        );

        if (servicesTable) {
            servicesTable.innerHTML = "";

            if (openResults.length === 0) {
                servicesTable.innerHTML = `
                    <tr>
                        <td colspan="5" class="loading">
                            No open ports detected
                        </td>
                    </tr>
                `;
            } else {
                openResults.forEach((result) => {
                    const row = document.createElement("tr");

                    row.innerHTML = `
                        <td>${result.port}</td>
                        <td>${result.service ?? "Unknown"}</td>
                        <td>${result.product ?? "Unknown"}</td>
                        <td>${result.version ?? "Unknown"}</td>
                        <td>
                            <span class="status-open">
                                OPEN
                            </span>
                        </td>
                    `;

                    servicesTable.appendChild(row);
                });
            }
        }

        if (portCountElement) {
            portCountElement.textContent =
                `${openResults.length} ${
                    openResults.length === 1
                        ? "port"
                        : "ports"
                }`;
        }

        // --------------------------------
        // Vulnerabilities
        // --------------------------------

        const vulnerabilitiesTable =
            document.querySelector("#vulnerabilities-table");

        const cveCountElement =
            document.querySelector("#cve-count");

        const vulnerabilities =
            detail.vulnerabilities || [];

        if (vulnerabilitiesTable) {
            vulnerabilitiesTable.innerHTML = "";

            if (vulnerabilities.length === 0) {
                vulnerabilitiesTable.innerHTML = `
                    <tr>
                        <td colspan="5" class="loading">
                            No vulnerabilities detected
                        </td>
                    </tr>
                `;
            } else {
                vulnerabilities.forEach((vulnerability) => {
                    const row = document.createElement("tr");

                    row.innerHTML = `
                        <td>${vulnerability.cve_id}</td>
                        <td>${vulnerability.product}</td>
                        <td>${vulnerability.version}</td>
                        <td>${vulnerability.severity}</td>
                        <td>${vulnerability.cvss_score}</td>
                    `;

                    vulnerabilitiesTable.appendChild(row);
                });
            }
        }

        if (cveCountElement) {
            cveCountElement.textContent =
                `${vulnerabilities.length} ${
                    vulnerabilities.length === 1
                        ? "CVE"
                        : "CVEs"
                }`;
        }

        // --------------------------------
        // Security Findings
        // --------------------------------

        const findingsList =
            document.querySelector("#findings-list");

        const securityFindings =
            detail.findings || [];

        if (findingsList) {
            findingsList.innerHTML = "";

            if (securityFindings.length === 0) {
                findingsList.innerHTML = `
                    <div class="loading">
                        No security findings detected
                    </div>
                `;
            } else {
                securityFindings.forEach((finding) => {
                    const findingElement =
                        document.createElement("div");

                    findingElement.className = "finding";

                    findingElement.innerHTML = `
                        <div>
                            <strong>${finding.title}</strong>
                            <span>${finding.severity}</span>
                        </div>

                        <p>${finding.description}</p>

                        <small>
                            Port ${finding.port}
                            ${finding.service
                                ? ` · ${finding.service}`
                                : ""}
                        </small>

                        <p>
                            <strong>Recommendation:</strong>
                            ${finding.recommendation}
                        </p>
                    `;

                    findingsList.appendChild(findingElement);
                });
            }
        }

        // --------------------------------
        // Debug information
        // --------------------------------

        console.log("Dashboard:", dashboard);
        console.log("Scan details:", detail);

    } catch (error) {
        console.error(
            "Dashboard loading failed:",
            error
        );
    }
}

// --------------------------------
// Start dashboard
// --------------------------------

document.addEventListener(
    "DOMContentLoaded",
    () => {
        loadDashboard();

        // Refresh every 30 seconds
        setInterval(
            loadDashboard,
            30000
        );
    }
);