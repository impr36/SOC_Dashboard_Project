"""
investigation_service.py
========================
AI-Assisted Investigation Center.

Dual-path architecture (exactly as described in the project report):
  Path 1: Ollama LLM (if available at localhost:11434)
  Path 2: Rule-based fallback (always available, no LLM needed)

Output always includes:
  - technical_assessment
  - executive_summary
  - beginner_explanation
  - attack_story
  - mitre_techniques
  - remediation_steps
  - risk_score
"""

import json
import urllib.request
import urllib.error
from datetime import datetime
from collections import Counter

# =========================================
# MITRE ATT&CK MAPPINGS
# =========================================

MITRE_MAP = {
    # Authentication / Credential
    "Brute Force Login Attempt":          ("T1110",     "Brute Force",                 "Credential Access"),
    "Account Lockout Triggered":          ("T1110",     "Brute Force",                 "Credential Access"),
    "Failed Login":                       ("T1110",     "Brute Force",                 "Credential Access"),
    "Successful Login After Failures":    ("T1078",     "Valid Accounts",              "Defense Evasion"),
    "Credential Theft Via Browser":       ("T1555.003", "Credentials from Browser",    "Credential Access"),
    "Credential Theft Browser Injection": ("T1555.003", "Credentials from Browser",    "Credential Access"),
    "Invoke-Mimikatz Execution":          ("T1003",     "OS Credential Dumping",       "Credential Access"),
    "LSASS Access Attempt":               ("T1003.001", "LSASS Memory",                "Credential Access"),
    "LSASS Memory Dump":                  ("T1003.001", "LSASS Memory",                "Credential Access"),
    "LSA Secret Dumping":                 ("T1003.004", "LSA Secrets",                 "Credential Access"),
    "MiniDump Credential Theft":          ("T1003.001", "LSASS Memory",                "Credential Access"),
    "Credential Manager Dump":            ("T1555",     "Credentials from Password Stores","Credential Access"),
    # Persistence
    "Startup Registry Modified":          ("T1547.001", "Registry Run Keys",           "Persistence"),
    "Task Scheduler Abuse":               ("T1053.005", "Scheduled Task",              "Persistence"),
    "Persistence Via WMI":                ("T1546.003", "WMI Event Subscription",      "Persistence"),
    "Persistence Via Winlogon Registry":  ("T1547.004", "Winlogon Helper DLL",         "Persistence"),
    "Persistence Via AppInit DLLs":       ("T1546.010", "AppInit DLLs",               "Persistence"),
    "Persistence Via Accessibility Features":("T1546.008","Accessibility Features",   "Persistence"),
    "Service Installed":                  ("T1543.003", "Windows Service",             "Persistence"),
    # Execution
    "Encoded PowerShell Command":         ("T1059.001", "PowerShell",                  "Execution"),
    "PowerShell Empire Activity":         ("T1059.001", "PowerShell",                  "Execution"),
    "PowerShell Reverse Shell":           ("T1059.001", "PowerShell",                  "Execution"),
    "Malicious Script Execution":         ("T1059",     "Command and Scripting Interpreter","Execution"),
    "Macro Spawned PowerShell":           ("T1566.001", "Spearphishing Attachment",    "Initial Access"),
    # Defense Evasion
    "Defender Tampering Attempt":         ("T1562.001", "Disable Security Tools",      "Defense Evasion"),
    "Tampered Windows Defender Exclusion":("T1562.001", "Disable Security Tools",      "Defense Evasion"),
    "Security Logging Disabled":          ("T1070.001", "Clear Windows Event Logs",    "Defense Evasion"),
    "Antimalware Scan Interface Disabled":("T1562.001", "Disable Security Tools",      "Defense Evasion"),
    # Lateral Movement
    "Remote WMI Execution":               ("T1021.006", "Windows Remote Management",   "Lateral Movement"),
    "PsExec Activity":                    ("T1569.002", "Service Execution",           "Lateral Movement"),
    "Remote Service Execution":           ("T1021",     "Remote Services",             "Lateral Movement"),
    # Reconnaissance
    "Unauthorized Network Scan":          ("T1046",     "Network Service Discovery",   "Reconnaissance"),
    "Firewall Rule Enumeration":          ("T1518.001", "Security Software Discovery", "Discovery"),
    "Systeminfo Reconnaissance":          ("T1082",     "System Information Discovery","Discovery"),
    "SharpHound Execution":               ("T1087",     "Account Discovery",           "Discovery"),
    # C2
    "Reverse Shell Connection":           ("T1071",     "Application Layer Protocol",  "Command and Control"),
    "Tor Exit Node Communication":        ("T1090.003", "Multi-hop Proxy",             "Command and Control"),
    "Advanced Persistent Beacon":         ("T1071",     "Application Layer Protocol",  "Command and Control"),
    # Exfiltration
    "RAR Exfiltration Activity":          ("T1560",     "Archive Collected Data",      "Collection"),
    "Suspicious Compression Before Upload":("T1560",    "Archive Collected Data",      "Collection"),
    "DNS Zone Transfer Attempt":          ("T1048.003", "Exfiltration Over Alternative Protocol","Exfiltration"),
    # Impact
    "Backup Deletion Activity":           ("T1490",     "Inhibit System Recovery",     "Impact"),
    "Ransom Note Creation":               ("T1486",     "Data Encrypted for Impact",   "Impact"),
    "Play Ransomware Activity":           ("T1486",     "Data Encrypted for Impact",   "Impact"),
}

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

REMEDIATION_MAP = {
    "Credential Access": [
        "Reset all passwords for affected accounts immediately",
        "Enable multi-factor authentication (MFA) on all accounts",
        "Audit privileged account access and remove unnecessary admin rights",
        "Deploy Windows Credential Guard to protect LSASS",
        "Enable Protected Users security group for sensitive accounts",
    ],
    "Persistence": [
        "Audit and remove all unauthorised registry Run keys",
        "Review and remove suspicious scheduled tasks",
        "Disable unused WMI subscriptions and event consumers",
        "Implement application whitelisting via AppLocker or WDAC",
        "Monitor startup folder and Winlogon keys via Group Policy",
    ],
    "Defense Evasion": [
        "Re-enable Windows Defender real-time protection immediately",
        "Restore audit log settings and verify SACL configuration",
        "Check all Defender exclusion rules and remove unauthorised entries",
        "Deploy Microsoft Defender for Endpoint tamper protection",
        "Review Group Policy for security policy modifications",
    ],
    "Execution": [
        "Enable PowerShell Constrained Language Mode",
        "Deploy PowerShell Script Block Logging and Module Logging",
        "Block macro execution in Office applications via Group Policy",
        "Restrict PowerShell execution policy to AllSigned or RemoteSigned",
        "Enable Windows Defender AMSI integration for script inspection",
    ],
    "Lateral Movement": [
        "Segment network and restrict lateral movement paths",
        "Disable unnecessary remote management protocols (WMI, WinRM, SMB)",
        "Enforce least-privilege principle for all service accounts",
        "Deploy network access control (NAC) for east-west traffic",
        "Enable Windows Firewall with Advanced Security rules",
    ],
    "Command and Control": [
        "Block C2 infrastructure at network perimeter firewall",
        "Enable DNS filtering to detect DNS tunnelling and beaconing",
        "Deploy network-based anomaly detection for beaconing patterns",
        "Investigate and isolate all affected endpoints immediately",
        "Review proxy and firewall logs for unauthorised outbound connections",
    ],
    "Reconnaissance": [
        "Review and restrict network scanning from internal hosts",
        "Enable network IDS/IPS to detect scanning activity",
        "Implement network segmentation to limit lateral discovery",
        "Audit and restrict LDAP and Active Directory enumeration",
    ],
}

# =========================================
# OLLAMA CLIENT
# =========================================

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODELS = ["llama3", "mistral", "qwen", "gemma2", "phi3", "llama2"]


def check_ollama() -> dict:
    """Check if Ollama is running and which models are available."""
    try:
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            models = [m["name"].split(":")[0] for m in data.get("models", [])]
            return {"available": True, "models": models}
    except Exception:
        return {"available": False, "models": []}


def _call_ollama(model: str, prompt: str, timeout: int = 60) -> str:
    """Call Ollama API synchronously."""
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 1500}
    }).encode()
    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        result = json.loads(resp.read().decode())
        return result.get("response", "")


def _build_prompt(alerts: list, context: str = "") -> str:
    alert_summary = "\n".join([
        f"- [{a.get('severity','?')}] {a.get('type','Unknown')} | "
        f"Category: {a.get('category','?')} | "
        f"Time: {str(a.get('timestamp','?'))[:19]} | "
        f"MITRE: {a.get('mitre_technique','?')} | "
        f"Desc: {str(a.get('description',''))[:120]}"
        for a in alerts[:30]
    ])

    severity_counts = Counter(a.get("severity","?") for a in alerts)
    categories = Counter(a.get("category","?") for a in alerts)

    return f"""You are a senior SOC analyst. Analyse the following security alerts and provide a structured investigation report.

ALERT SUMMARY ({len(alerts)} total alerts):
Severity: {dict(severity_counts)}
Categories: {dict(categories)}

ALERTS:
{alert_summary}

{f"ADDITIONAL CONTEXT: {context}" if context else ""}

Provide a JSON response with exactly these fields:
{{
  "technical_assessment": "Detailed technical analysis of what happened, which systems are affected, attack vectors used, and confidence level",
  "executive_summary": "2-3 sentence management-level summary of the incident and business impact",
  "beginner_explanation": "Plain language explanation for non-technical staff — what happened and why it matters",
  "attack_story": "Narrative of the attack phases: initial access, execution, persistence, lateral movement, objectives",
  "risk_score": <integer 0-100>,
  "attack_phase": "one of: Reconnaissance / Initial Access / Execution / Persistence / Privilege Escalation / Defense Evasion / Credential Access / Discovery / Lateral Movement / Collection / Command and Control / Exfiltration / Impact",
  "immediate_actions": ["action1", "action2", "action3"],
  "affected_systems": ["system or account name"],
  "ioc_indicators": ["specific IOC from the alerts"]
}}

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON."""


# =========================================
# RULE-BASED FALLBACK ENGINE
# =========================================

def _rule_based_analysis(alerts: list) -> dict:
    """
    Complete rule-based analysis that mirrors the LLM output format.
    Runs without any AI dependency.
    """
    if not alerts:
        return {"error": "No alerts provided"}

    # Count severities and categories
    sev_counts   = Counter(a.get("severity","LOW") for a in alerts)
    cat_counts   = Counter(a.get("category","Others") for a in alerts)
    alert_types  = Counter(a.get("type","Unknown") for a in alerts)
    total        = len(alerts)

    # Risk score: weighted sum capped at 100
    raw_score = sum(SEVERITY_WEIGHTS.get(s,1) * c for s,c in sev_counts.items())
    risk_score = min(100, int(raw_score / max(1, total) * 10))
    if sev_counts.get("CRITICAL",0) >= 5:  risk_score = max(risk_score, 85)
    if sev_counts.get("CRITICAL",0) >= 10: risk_score = max(risk_score, 95)

    # Determine dominant attack phase
    phase_priority = [
        ("Impact",              ["Impact","Ransomware"]),
        ("Exfiltration",        ["Exfiltration","Data Exfiltration"]),
        ("Command and Control", ["Command and Control","Command & Control"]),
        ("Lateral Movement",    ["Lateral Movement"]),
        ("Credential Access",   ["Credential Access"]),
        ("Privilege Escalation",["Privilege Escalation"]),
        ("Defense Evasion",     ["Defense Evasion"]),
        ("Persistence",         ["Persistence"]),
        ("Execution",           ["Execution"]),
        ("Initial Access",      ["Authentication","Initial Access"]),
        ("Reconnaissance",      ["Reconnaissance","Discovery"]),
    ]
    attack_phase = "Execution"
    for phase, cats in phase_priority:
        if any(cat_counts.get(c,0) > 0 for c in cats):
            attack_phase = phase
            break

    # Top 3 alert types
    top_types = [t for t,_ in alert_types.most_common(5)]

    # MITRE techniques
    mitre_seen = {}
    for a in alerts:
        t = a.get("type","")
        if t in MITRE_MAP:
            tid, tname, tactic = MITRE_MAP[t]
            mitre_seen[tid] = {"id": tid, "name": tname, "tactic": tactic, "count": mitre_seen.get(tid,{}).get("count",0)+1}
    mitre_techniques = list(mitre_seen.values())[:8]

    # Gather remediation from top categories
    remediation = []
    for cat,_ in cat_counts.most_common(3):
        steps = REMEDIATION_MAP.get(cat, [])
        remediation.extend(steps)
    remediation = list(dict.fromkeys(remediation))[:8]  # deduplicate

    # Severity label
    if risk_score >= 80:   threat_level = "CRITICAL"
    elif risk_score >= 60: threat_level = "HIGH"
    elif risk_score >= 40: threat_level = "MEDIUM"
    else:                  threat_level = "LOW"

    # Top categories string
    top_cats = ", ".join(f"{c} ({n})" for c,n in cat_counts.most_common(4))
    crit  = sev_counts.get("CRITICAL",0)
    high  = sev_counts.get("HIGH",0)
    med   = sev_counts.get("MEDIUM",0)
    low   = sev_counts.get("LOW",0)

    timestamps = sorted([str(a.get("timestamp","")) for a in alerts if a.get("timestamp")])
    time_range = ""
    if len(timestamps) >= 2:
        time_range = f" between {timestamps[0][:19]} and {timestamps[-1][:19]}"

    technical = (
        f"Analysis of {total} security alerts{time_range} reveals a {threat_level}-severity incident "
        f"with {crit} CRITICAL, {high} HIGH, {med} MEDIUM, and {low} LOW alerts. "
        f"Dominant threat categories: {top_cats}. "
        f"Primary attack phase identified as {attack_phase}. "
        f"Top alert types: {', '.join(top_types[:3])}. "
        f"Risk score: {risk_score}/100. "
        f"The pattern suggests {'active compromise and potential data breach' if risk_score >= 80 else 'suspicious activity requiring immediate investigation' if risk_score >= 60 else 'security policy violations requiring review'}."
    )

    executive = (
        f"The system detected {total} security alerts indicating a {threat_level.lower()} threat "
        f"({crit} critical events). "
        f"The primary concern is {attack_phase.lower()} activity. "
        f"Immediate response is {'required' if risk_score >= 60 else 'recommended'}."
    )

    beginner = (
        f"Your computer's security monitoring found {total} suspicious events. "
        f"Think of it like a security camera that spotted {crit + high} serious incidents "
        f"and {med + low} minor ones. "
        f"The most concerning activity is: {top_types[0] if top_types else 'suspicious behaviour'}. "
        f"{'Your system may be under active attack and needs immediate attention.' if risk_score >= 80 else 'These events need to be reviewed and investigated.'}"
    )

    story_phases = []
    if cat_counts.get("Authentication",0) + cat_counts.get("Credential Access",0) > 0:
        story_phases.append("The attacker began by targeting authentication mechanisms to gain initial access")
    if cat_counts.get("Execution",0) > 0:
        story_phases.append("Malicious code or scripts were then executed on the system")
    if cat_counts.get("Persistence",0) > 0:
        story_phases.append("The attacker established persistence mechanisms to maintain access after reboots")
    if cat_counts.get("Defense Evasion",0) > 0:
        story_phases.append("Security controls were actively disabled or tampered with to avoid detection")
    if cat_counts.get("Lateral Movement",0) > 0:
        story_phases.append("The attacker moved laterally across the network to reach additional systems")
    if cat_counts.get("Command and Control",0) + cat_counts.get("Command & Control",0) > 0:
        story_phases.append("C2 communication channels were established to control compromised systems remotely")
    if cat_counts.get("Impact",0) + cat_counts.get("Ransomware",0) > 0:
        story_phases.append("Impact-phase activity detected — potential data encryption or destruction underway")
    if not story_phases:
        story_phases = [f"Suspicious {attack_phase.lower()} activity detected across {total} events"]
    attack_story = ". ".join(story_phases) + "."

    immediate_actions = [
        f"Isolate affected systems immediately — {crit} critical events require containment",
        "Reset all credentials for accounts involved in these alerts",
        "Preserve all log evidence before taking remediation actions",
        "Notify your security team and initiate incident response protocol",
        "Review and re-enable any disabled security controls",
    ]
    if remediation:
        immediate_actions.extend(remediation[:3])

    return {
        "technical_assessment": technical,
        "executive_summary":    executive,
        "beginner_explanation": beginner,
        "attack_story":         attack_story,
        "risk_score":           risk_score,
        "attack_phase":         attack_phase,
        "threat_level":         threat_level,
        "immediate_actions":    immediate_actions[:6],
        "mitre_techniques":     mitre_techniques,
        "remediation_steps":    remediation,
        "alert_summary": {
            "total":    total,
            "critical": crit,
            "high":     high,
            "medium":   med,
            "low":      low,
            "top_categories": dict(cat_counts.most_common(6)),
            "top_types":      dict(alert_types.most_common(5)),
        },
        "generated_by": "rule_based_fallback",
        "generated_at": datetime.now().isoformat(),
    }


# =========================================
# MAIN INVESTIGATION FUNCTION
# =========================================

def investigate(alerts: list, context: str = "") -> dict:
    """
    Main entry point. Tries Ollama first, falls back to rule-based.
    Always returns the same output schema.
    """
    if not alerts:
        return {"error": "No alerts provided for investigation"}

    # Try Ollama
    status = check_ollama()
    if status["available"] and status["models"]:
        model = status["models"][0]
        try:
            prompt   = _build_prompt(alerts, context)
            raw      = _call_ollama(model, prompt, timeout=90)
            # Strip markdown fences if present
            clean = raw.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            parsed = json.loads(clean.strip())
            parsed["generated_by"]    = f"ollama:{model}"
            parsed["generated_at"]    = datetime.now().isoformat()
            parsed["mitre_techniques"] = _extract_mitre(alerts)
            parsed["remediation_steps"] = _extract_remediation(alerts)
            parsed["alert_summary"]    = _build_summary(alerts)
            return parsed
        except Exception as e:
            print(f"[INVESTIGATE] Ollama failed ({e}), using rule-based fallback")

    # Rule-based fallback
    result = _rule_based_analysis(alerts)
    result["ollama_status"] = status
    return result


def _extract_mitre(alerts: list) -> list:
    seen = {}
    for a in alerts:
        t = a.get("type","")
        if t in MITRE_MAP:
            tid, tname, tactic = MITRE_MAP[t]
            seen[tid] = {"id": tid, "name": tname, "tactic": tactic,
                         "count": seen.get(tid, {}).get("count",0) + 1}
    return list(seen.values())[:10]


def _extract_remediation(alerts: list) -> list:
    cats = set(a.get("category","") for a in alerts)
    steps = []
    for cat in cats:
        steps.extend(REMEDIATION_MAP.get(cat, []))
    return list(dict.fromkeys(steps))[:8]


def _build_summary(alerts: list) -> dict:
    sev = Counter(a.get("severity","?") for a in alerts)
    cats = Counter(a.get("category","?") for a in alerts)
    types = Counter(a.get("type","?") for a in alerts)
    return {
        "total": len(alerts),
        "critical": sev.get("CRITICAL",0),
        "high": sev.get("HIGH",0),
        "medium": sev.get("MEDIUM",0),
        "low": sev.get("LOW",0),
        "top_categories": dict(cats.most_common(6)),
        "top_types": dict(types.most_common(5)),
    }
