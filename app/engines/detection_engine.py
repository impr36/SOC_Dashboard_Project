from datetime import datetime

from app.rules.rules import KEYWORD_RULES

from app.engines.mitre_mapper import (
    map_mitre
)



# =========================================
# SOC TERMINAL LOGGER
# =========================================
def _soc_log(msg: str):
    print(msg)
    try:
        from app.websocket_manager import manager
        manager.send_console(str(msg))
    except Exception:
        pass



# =========================================
# FIELD MAP — Sigma field → normalized key
# =========================================

FIELD_MAP = {

    "Image":           "image",
    "CommandLine":     "commandline",
    "ParentImage":     "parentimage",
    "DestinationIp":   "destinationip",
    "DestinationPort": "destinationport",
    "QueryName":       "queryname",
    "QueryResults":    "queryresults",
    "TargetObject":    "targetobject",
    "Details":         "details",
    "User":            "user",
    "EventID":         "eventid",

    # snake_case aliases (log sources that
    # arrive pre-normalised)
    "image":           "image",
    "commandline":     "commandline",
    "command_line":    "commandline",
    "parentimage":     "parentimage",
    "parent_process":  "parentimage",
    "destinationip":   "destinationip",
    "destination_ip":  "destinationip",
    "destinationport": "destinationport",
    "destination_port":"destinationport",
    "queryname":       "queryname",
    "query_name":      "queryname",
    "queryresults":    "queryresults",
    "query_results":   "queryresults",
    "targetobject":    "targetobject",
    "target_object":   "targetobject",
    "details":         "details",
    "user":            "user",
    "eventid":         "eventid",
    "event_id":        "eventid",

    # Extra Sysmon / network fields
    "SourceIp":        "sourceip",
    "sourceip":        "sourceip",
    "source_ip":       "sourceip",
    "Protocol":        "protocol",
    "protocol":        "protocol",
    "ProcessName":     "processname",
    "processname":     "processname",
    "process_name":    "processname",
    "description":     "description",
    "Description":     "description",
    "source":          "source",
    "Source":          "source",
    "category":        "category",
    "Category":        "category",
    "computer":        "computer",
    "Computer":        "computer",
    "ip_address":      "ipaddress",
    "IpAddress":       "ipaddress",
}


# =========================================
# SOURCE CLASSIFICATION
# Maps the log's source string → HIDS/NIDS.
# Driven entirely by what the log sends —
# no hostnames or machine names hardcoded.
# =========================================

HIDS_SOURCES = {
    "sysmon", "security", "defender",
    "registry", "task", "wmi", "hids",
    "taskscheduler", "microsoft-windows",
    "powershell", "system", "application",
    "sam", "lsa", "audit",
}

NIDS_SOURCES = {
    "network", "firewall", "dns", "smb",
    "rdp", "nids", "snort", "suricata",
    "zeek", "bro", "palo", "fortinet",
    "cisco", "netflow", "pcap", "proxy",
    "web", "http", "ftp", "smtp",
}


def classify_log_source(source_str, rule):
    """
    Classify a log as HIDS or NIDS based on its
    source field. Falls back to the rule's own
    rule_type if source is ambiguous or empty.
    No hostnames or machine names involved.
    """
    s = str(source_str).lower().strip()

    for token in HIDS_SOURCES:
        if token in s:
            return "HIDS"

    for token in NIDS_SOURCES:
        if token in s:
            return "NIDS"

    # Final fallback: use what the rule itself says
    return str(rule.get("rule_type", "HIDS")).upper()

def determine_category(name):

    n = str(name).lower()

    if any(x in n for x in [
        "mimikatz", "credential", "lsass", "sam dump"
    ]):
        return "Credential Access"

    elif any(x in n for x in [
        "powershell", "execution", "script", "cmd.exe"
    ]):
        return "Execution"

    elif any(x in n for x in [
        "ransomware", "encrypted", ".locked"
    ]):
        return "Ransomware"

    elif any(x in n for x in [
        "scan", "recon", "nmap", "masscan"
    ]):
        return "Reconnaissance"

    elif any(x in n for x in [
        "service", "startup", "persistence",
        "autorun", "scheduled task"
    ]):
        return "Persistence"

    elif any(x in n for x in [
        "privilege", "token", "admin", "uac"
    ]):
        return "Privilege Escalation"

    elif any(x in n for x in [
        "login", "authentication", "logon",
        "bruteforce", "failed login"
    ]):
        return "Authentication"

    elif any(x in n for x in [
        "defender", "evasion", "disable security"
    ]):
        return "Defense Evasion"

    elif any(x in n for x in [
        "tamper", "registry", "integrity", "file"
    ]):
        return "System Tampering"

    elif any(x in n for x in [
        "lateral", "smb", "rdp", "psexec"
    ]):
        return "Lateral Movement"

    return "Others"


# =========================================
# SIGMA OPERATOR MATCHER
# =========================================

def sigma_match(field_value, rule_value, operator="contains"):
    """
    Evaluate a single Sigma field condition.

    Supported operators:
        contains    — rule_value is a substring of field_value
        startswith  — field_value begins with rule_value
        endswith    — field_value ends with rule_value
        equals      — exact match
        re          — treated as contains (regex support future)
    """

    field_value = str(field_value).lower()

    if not field_value.strip():
        return False
        # ANY item in the list must match (Sigma "contains|all" handled
        # separately at selection level)
        return any(
            sigma_match(field_value, str(rv).lower(), operator)
            for rv in rule_value
        )

    rule_value = str(rule_value).lower()

    if not rule_value:
        return False

    if operator == "contains":
        return rule_value in field_value

    elif operator == "startswith":
        return field_value.startswith(rule_value)

    elif operator == "endswith":
        return field_value.endswith(rule_value)

    elif operator == "equals":
        return field_value == rule_value

    elif operator == "re":
        # fallback: treat as contains
        return rule_value in field_value

    return False


# =========================================
# NORMALIZE LOG ROW → flat dict
# =========================================

def normalize_log(row):
    """
    Build a flat, lowercase, Sigma-compatible
    normalized dict from a raw log row.
    Accepts both camelCase Sysmon keys and
    snake_case ingestion keys.
    """

    def g(key, fallback=""):
        import math
        val = row.get(key, fallback)
        # Pandas NaN / None → empty string, never "nan"
        if val is None:
            return ""
        if isinstance(val, float) and math.isnan(val):
            return ""
        return str(val).lower()

    return {

        "image":           g("Image") or g("process_name"),
        "commandline":     g("CommandLine") or g("command_line"),
        "parentimage":     g("ParentImage") or g("parent_process"),
        "destinationip":   g("DestinationIp") or g("destination_ip"),
        "destinationport": g("DestinationPort") or g("destination_port"),
        "sourceip":        g("SourceIp") or g("source_ip") or g("ip_address"),
        "queryname":       g("QueryName") or g("query_name"),
        "queryresults":    g("QueryResults") or g("query_results"),
        "targetobject":    g("TargetObject") or g("target_object"),
        "details":         g("Details") or g("details"),
        "user":            g("User") or g("user"),
        "eventid":         g("EventID") or g("event_id"),
        "processname":     (
            g("ProcessName")
            or g("process_name")
            or g("Image")
        ),
        "protocol":        g("Protocol") or g("protocol"),
        "description":     g("description"),
        "source":          g("source"),
        "category":        g("category"),
        "computer":        g("Computer") or g("computer"),
        "ipaddress":       g("ip_address") or g("IpAddress"),

        # raw blob for plain keyword fallback
        "raw": " ".join([
            g("description"),
            g("ProcessName") or g("process_name"),
            g("source"),
            g("raw_log") or g("raw_data"),
            g("EventID") or g("event_id"),
            g("category"),
            g("ip_address"),
            g("user"),
            g("computer"),
            g("CommandLine") or g("command_line"),
            g("ParentImage") or g("parent_process"),
            g("DestinationIp") or g("destination_ip"),
            g("DestinationPort") or g("destination_port"),
            g("TargetObject") or g("target_object"),
            g("Details") or g("details"),
            g("QueryName") or g("query_name"),
            g("QueryResults") or g("query_results"),
            g("Image") or g("process_name"),
        ]).lower(),
    }


# =========================================
# SIGMA SELECTION EVALUATOR
# =========================================

def evaluate_sigma_selection(selection, normalized_log):
    """
    Evaluate a Sigma `detection.selection` dict
    against a normalized log.

    Handles:
      - Field|contains
      - Field|startswith
      - Field|endswith
      - Field|equals
      - Field|contains|all   (all items in list must match)
      - plain Field           (default contains)
    """

    for sigma_key, sigma_value in selection.items():

        # Parse "Field|operator" or "Field|op1|op2"
        parts = sigma_key.split("|")
        field = parts[0]
        operator = parts[1] if len(parts) > 1 else "contains"
        modifier = parts[2] if len(parts) > 2 else None  # e.g. "all"

        # Resolve field name
        normalized_field = FIELD_MAP.get(field)

        if not normalized_field:
            # Unknown field — skip this rule entirely
            # (raw blob fallback caused 3M+ false positives)
            return False

        log_value = normalized_log.get(normalized_field, "")

        # "contains|all" — every item must match
        if modifier == "all" and isinstance(sigma_value, list):

            if not all(
                sigma_match(log_value, str(v), operator)
                for v in sigma_value
            ):
                return False

        else:
            # Default: ANY item in list matches (OR)
            if not sigma_match(log_value, sigma_value, operator):
                return False

    return True


# =========================================
# KEYWORD FALLBACK MATCHER
# =========================================

def match_keywords(keywords, normalized_log):
    """
    Plain keyword matching against the raw
    blob — used when no Sigma detection block
    is present.
    Returns the first matched keyword or None.
    """

    raw = normalized_log.get("raw", "")

    for keyword in keywords:

        kw = str(keyword).lower().strip()

        if kw and kw in raw:
            return kw

    return None


# =========================================
# THRESHOLD ENGINE
# Counts event_id occurrences per host
# within a rolling time window (window_min).
# Fires an alert when count >= threshold.
# This is the PRIMARY engine for your rules
# since ALL 1419 rules use threshold+window.
# =========================================


# =========================================
# FAKE EVENT ID DETECTION
# Rules generated from JSON use sequential
# event_ids 1001-2000 (HIDS) and 3001-3500
# (NIDS) that don't exist in real Windows logs.
# Only ~69 rules have real event_ids.
# =========================================

# Real Windows/Sysmon/Defender event ID ranges
# Everything outside these is treated as "fake"
def _is_real_event_id(eid_str):
    try:
        eid = int(eid_str)
        # Sysmon: 1-26
        if 1 <= eid <= 26:
            return True
        # Windows Security: 4000-5999
        if 4000 <= eid <= 5999:
            return True
        # Windows System/App: 6000-8000
        if 6000 <= eid <= 8000:
            return True
        # Defender/AV: known real IDs
        if eid in {1000,1001,1002,1006,1007,1008,1013,1015,1116,1117,1118,1119,1120,2000,2001,2002,2003,2004,2005,3002,3004,7023,7031,7034,7040,7045}:
            return True
        # PowerShell: 400,403,600,800
        if eid in {400,403,600,800}:
            return True
        # WMI: 5860,5861
        if eid in {5860,5861}:
            return True
        return False
    except (ValueError, TypeError):
        return False


def run_threshold_engine(df):

    from collections import defaultdict
    import math

    alerts = []
    seen   = set()

    # ── Pre-process all log rows once ──────────────────────────────
    # Build three indexes:
    #   event_index  : { event_id_str : [(ts_float, row), ...] }
    #   source_index : { "hids"|"nids" : [(ts_float, row), ...] }
    #   all_rows     : [(ts_float, row), ...]  (for very broad rules)

    event_index  = defaultdict(list)
    source_index = defaultdict(list)   # "hids" or "nids"

    for _, row in df.iterrows():

        eid = str(
            row.get("event_id", row.get("EventID", ""))
        ).strip()

        ts_raw = row.get("timestamp", None)
        try:
            if hasattr(ts_raw, "timestamp"):
                ts = ts_raw.timestamp()
            else:
                from datetime import datetime as dt
                ts = dt.fromisoformat(
                    str(ts_raw).replace("Z", "+00:00")
                ).timestamp()
        except Exception:
            ts = 0.0

        if eid:
            event_index[eid].append((ts, row))

        # classify log into hids/nids bucket
        src = str(row.get("source", "")).lower()
        log_class = "nids" if any(t in src for t in NIDS_SOURCES) else "hids"
        source_index[log_class].append((ts, row))

    # ── Pre-build inverted keyword index ──────────────────────────
    # Instead of scanning all 14k rows per rule (14k*925=13M ops),
    # build: token → [(ts, row)]. Cost: 14k rows × tokens, done ONCE.
    from collections import defaultdict as _dd
    keyword_inverted = _dd(list)
    hids_rows_bucket = []
    nids_rows_bucket = []

    for _, row in df.iterrows():
        ts_raw = row.get("timestamp", None)
        try:
            if hasattr(ts_raw, "timestamp"):
                ts = ts_raw.timestamp()
            else:
                from datetime import datetime as dt
                ts = dt.fromisoformat(
                    str(ts_raw).replace("Z", "+00:00")
                ).timestamp()
        except Exception:
            ts = 0.0

        normed = normalize_log(row)
        raw_blob = normed.get("raw", "")
        src = str(row.get("source", "")).lower()
        is_nids = any(t in src for t in NIDS_SOURCES)

        if is_nids:
            nids_rows_bucket.append((ts, row))
        else:
            hids_rows_bucket.append((ts, row))

        for token in set(raw_blob.split()):
            if len(token) >= 3:
                keyword_inverted[token].append((ts, row))

    # ── Evaluate each rule ─────────────────────────────────────────
    for rid, rule in KEYWORD_RULES.items():

        threshold  = rule.get("threshold")
        window_min = rule.get("window_min")

        if not threshold or not window_min:
            continue

        rule_eid   = str(rule.get("event_id", "")).strip()
        rule_type  = str(rule.get("rule_type", "HIDS")).upper()
        keywords   = rule.get("keywords", [])
        window_sec = float(window_min) * 60

        # ── Choose candidate log entries for this rule ────────────
        # Strategy:
        #   1. Real event_id → use event_index (exact match, fast)
        #   2. Fake event_id + keywords → keyword-matched entries
        #   3. Fake event_id + no keywords → source-bucket entries

        if rule_eid and _is_real_event_id(rule_eid):
            # Path 1: Real event_id
            entries = event_index.get(rule_eid, [])

        elif keywords:
            # Path 2: inverted index — O(keywords) not O(rows×rules)
            bucket = "nids" if rule_type == "NIDS" else "hids"
            kws = [str(k).lower().strip() for k in keywords if k]
            seen_rows = {}
            for kw in kws:
                for ts, raw_row in keyword_inverted.get(kw, []):
                    src = str(raw_row.get("source", "")).lower()
                    is_nids = any(t in src for t in NIDS_SOURCES)
                    if ("nids" if is_nids else "hids") == bucket:
                        row_id = id(raw_row)
                        if row_id not in seen_rows:
                            seen_rows[row_id] = (ts, raw_row)
            entries = list(seen_rows.values())
        else:
            # Path 3: no keywords, no real event_id → skip
            # (would match every log in the bucket = noise)
            continue

        if not entries:
            continue

        # ── Sliding window per host ───────────────────────────────
        by_host = defaultdict(list)
        for ts, row in entries:
            host = str(row.get("computer", row.get("Computer", "unknown")))
            by_host[host].append((ts, row))

        for host, host_entries in by_host.items():

            host_entries.sort(key=lambda x: x[0])
            window = []

            for ts, row in host_entries:

                window.append((ts, row))
                window = [
                    (t, r) for t, r in window
                    if ts - t <= window_sec
                ]

                if len(window) >= int(threshold):

                    normalized = normalize_log(row)
                    source     = normalized["source"]

                    ts_val = row.get("timestamp", datetime.now().isoformat())
                    if hasattr(ts_val, "isoformat"):
                        ts_val = ts_val.isoformat()
                    else:
                        ts_val = str(ts_val)

                    description = (
                        str(row.get("description", row.get("Description", "")))
                        or rule.get("description", "")
                    )

                    category = (
                        rule.get("mitre_tactic")
                        or determine_category(rule.get("name", ""))
                    )

                    log_source = classify_log_source(source, rule)

                    alert = {
                        "timestamp":        ts_val,
                        "event_id":         rule_eid,
                        "type":             str(rule.get("name", "Threshold Alert")),
                        "severity":         str(rule.get("severity", "MEDIUM")).upper(),
                        "description":      description,
                        "category":         category,
                        "explanation":      (
                            f"Threshold crossed: "
                            f"{len(window)}/{threshold} "
                            f"events in {window_min}min on {host}"
                        ),
                        "matched_keyword":  f"threshold:{rule_eid}",
                        "raw_log":          normalized["raw"][:3000],
                        "log_source":       log_source,
                    }

                    sig = (rule_eid, str(alert["type"]), host)

                    if sig not in seen:
                        seen.add(sig)
                        alert = map_mitre(alert)
                        alerts.append(alert)
                        _soc_log(
                            f"[THRESHOLD] "
                            f"{alert['type']} | "
                            f"{alert['severity']} | "
                            f"host={host} | "
                            f"{len(window)}/{threshold} hits"
                        )

                    window = []

    return alerts


# =========================================
# MAIN DETECTION ENGINE
# =========================================

def detect_advanced_threats(df):

    alerts = []
    seen   = set()

    if df.empty:
        return alerts

    _soc_log(f"[SOC] Logs received for detection: {len(df)}")
    _soc_log(f"[SOC] Rules loaded: {len(KEYWORD_RULES)}")

    # =========================================
    # PATH A — THRESHOLD ENGINE
    # Primary path. Handles all 1419 rules
    # that use threshold + window_min fields.
    # =========================================

    threshold_alerts = run_threshold_engine(df)
    alerts.extend(threshold_alerts)
    _soc_log(f"[SOC] Threshold alerts: {len(threshold_alerts)}")

    total_matches = 0

    # =========================================
    # PATH B — KEYWORD / SIGMA ENGINE
    # Disabled: current rules use threshold+
    # window only. Generic auto-extracted
    # keywords produce too many false positives
    # (3M+ alerts). Re-enable when rules carry
    # precise detection{} Sigma blocks.
    # =========================================

    # for index, row in df.iterrows():
    #     ... (keyword/sigma loop disabled)
    # =====================================
    # SORT BY SEVERITY
    # =====================================

    alerts.sort(

        key=lambda x: {
            "CRITICAL": 4,
            "HIGH":     3,
            "MEDIUM":   2,
            "LOW":      1
        }.get(x.get("severity", "LOW"), 1),

        reverse=True
    )

    _soc_log(f"[SOC] Total Matches: {total_matches}")
    _soc_log(f"[SOC] Final Alerts Generated: {len(alerts)}")

    if not alerts:
        _soc_log("[SOC] No threats detected.")

    return alerts