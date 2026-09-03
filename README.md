# SOC Detection & Incident Investigation — Wazuh

An end-to-end SOC portfolio project demonstrating Windows endpoint monitoring, alert triage, threat hunting, detection engineering, event correlation, vulnerability remediation, security configuration assessment, false-positive analysis, and analyst reporting.

## Project Overview

I deployed a single-node Wazuh environment with Docker and connected a Windows 11 endpoint. I collected Windows Security, Sysmon, File Integrity Monitoring, vulnerability, software-inventory, and Security Configuration Assessment telemetry. I then generated controlled activity, investigated the resulting alerts, developed and boundary-tested a custom detection, and documented evidence-based verdicts.

> **Public-release note:** Personal identifiers have been pseudonymized. `LAB-WIN11` and `AnalystUser` represent the original lab endpoint and analyst account; private IPv4 and machine-SID components are masked.

## Full Case Study

**[Read the complete case study (PDF)](SOC-Wazuh-Case-Study.pdf)**

The report contains the investigation methodology, supporting evidence, timelines, analyst interpretations, limitations, verdicts, remediation validation, and tuning recommendations.

## Lab Environment

| Component | Implementation |
| --- | --- |
| Endpoint | Windows 11 Pro (`LAB-WIN11`) |
| SIEM/XDR | Wazuh 4.14.7 |
| Deployment | Docker single-node |
| Telemetry | Windows Security, Sysmon, FIM, inventory, vulnerability detection, SCA |
| Sysmon coverage | Event 1 process creation, Event 3 network connection, Event 11 file creation |
| Custom rules | `/var/ossec/etc/rules/local_rules.xml` |

## Investigation Coverage

- Deployed and validated the Wazuh manager, indexer, dashboard, and Windows agent.
- Investigated file creation, modification, and deletion through FIM.
- Analyzed PowerShell execution using Sysmon process-creation telemetry.
- Investigated failed authentication and Windows account-lifecycle activity.
- Analyzed process-level network activity using Sysmon Event ID 3.
- Correlated account creation, privilege assignment, PowerShell execution, and outbound TCP activity.
- Investigated and remediated a high-severity Docker Desktop vulnerability.
- Validated and remediated a failed CIS minimum-password-length control.
- Independently investigated a level-15 alert and reached a defensible false-positive verdict.

## Custom Detection Engineering

The final custom rule promotes Wazuh's built-in level-0 PowerShell TCP classification into an analyst-visible level-8 alert:

```text
61605 — Generic Sysmon Event ID 3 classifier (level 0)
  └── 92101 — PowerShell communicating over TCP (level 0)
        └── 100100 — Custom analyst-visible alert (level 8)
```

Validation included:

- **Positive test:** Controlled PowerShell TCP connection triggered rule `100100`.
- **Negative boundary test:** Equivalent non-PowerShell network activity did not trigger rule `100100`.
- **Language correction:** The alert states that a connection was *observed* because parent rule `92101` does not guarantee `initiated:true`.
- **ATT&CK caution:** `T1059.001` is directly supported; inherited `T1095` context was not treated as proof of command-and-control.

The final XML is available in [`rules/local_rules.xml`](rules/local_rules.xml).

## Correlated Sequence

The controlled sequence linked:

1. Account creation and enablement
2. Addition to the local Administrators group
3. PowerShell process creation
4. Outbound PowerShell TCP activity
5. Verified removal and account deletion

Correlation relied on the target SID, actor and Logon ID, Process GUID, PID, timestamps, and network tuple—not timing alone.

## Independent Investigation

A level-15 file-creation alert identified a temporary PowerShell policy-test script under the user's Temp directory. I recovered archived process provenance and evaluated the parent process, digital signature, related file activity, child processes, network connections, and the exact rule conditions.

**Verdict:** High-confidence benign positive / operational false positive.

The rule correctly matched its path-and-extension heuristic, but the surrounding evidence did not support malicious execution or ingress-tool transfer. The recommended tuning is a narrow contextual exception for the expected policy-test pattern—not broad suppression of Temp-directory PowerShell scripts.

## Repository Structure

```text
.
├── README.md
├── SOC-Wazuh-Case-Study.pdf
├── evidence/
│   ├── 01-custom-rule.png
│   ├── 02-custom-rule-alert.png
│   ├── 03-correlated-sequence.png
│   ├── 04-cleanup-validation.png
│   ├── 05-vulnerability-details.png
│   ├── 06-remediation-health.png
│   ├── 07-cve-cleared.png
│   ├── 08-sca-control-passed.png
│   ├── 09-independent-alert-queue.png
│   └── 10-archived-process-provenance.png
└── rules/
    └── local_rules.xml
```

## Skills Demonstrated

`Wazuh` · `SIEM` · `Sysmon` · `Windows Event Logs` · `Docker` · `PowerShell` · `Threat Hunting` · `Alert Triage` · `Detection Engineering` · `MITRE ATT&CK` · `Event Correlation` · `Vulnerability Management` · `File Integrity Monitoring` · `False-Positive Analysis`

## Scope and Ethics

All triggering activity was performed in an isolated personal lab for authorized defensive-security testing. Alert severity and ATT&CK mappings are treated as analytical context rather than automatic proof of malicious intent.
