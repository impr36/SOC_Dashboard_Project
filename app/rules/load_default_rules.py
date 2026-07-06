import json

from pathlib import Path

from app.database.database import (

    insert_rule,
    fetch_rules
)

# =========================================
# RULE FILES
# =========================================

RULES_DIR = Path(__file__).resolve().parent

HIDS_RULES_FILE = RULES_DIR / "hids_rules.json"

NIDS_RULES_FILE = RULES_DIR / "nids_rules.json"

# =========================================
# NORMALIZE RULES
# =========================================

def normalize_rules(rules, rule_type):

    normalized = []

    # =====================================
    # DICTIONARY FORMAT
    # =====================================

    if isinstance(rules, dict):

        for i, (rule_name, rule_data) in enumerate(

            rules.items(),
            start=1
        ):

            normalized.append({

                "rule_type":
                    rule_type,

                "event_id":
                    rule_data.get(
                        "event_id",
                        i
                    ),

                "rule_name":
                    rule_name,

                "threshold":
                    rule_data.get(
                        "threshold",
                        1
                    ),

                "window_sec":
                    rule_data.get(
                        "window_sec",
                        rule_data.get(
                            "window_min",
                            1
                        ) * 60
                    ),

                "severity":
                    rule_data.get(
                        "severity",
                        "LOW"
                    ),

                "description":
                    rule_data.get(
                        "description",
                        ""
                    ),

                "mitre_tactic":
                    rule_data.get(
                        "mitre_tactic",
                        ""
                    ),

                "mitre_technique":
                    rule_data.get(
                        "mitre_technique",
                        ""
                    )
            })

    # =====================================
    # LIST FORMAT
    # =====================================

    elif isinstance(rules, list):

        for i, rule_data in enumerate(

            rules,
            start=1
        ):

            normalized.append({

                "rule_type":
                    rule_type,

                "event_id":
                    rule_data.get(
                        "event_id",
                        i
                    ),

                "rule_name":
                    rule_data.get(
                        "rule_name",
                        f"{rule_type} Rule {i}"
                    ),

                "threshold":
                    rule_data.get(
                        "threshold",
                        1
                    ),

                "window_sec":
                    rule_data.get(
                        "window_sec",
                        rule_data.get(
                            "window_min",
                            1
                        ) * 60
                    ),

                "severity":
                    rule_data.get(
                        "severity",
                        "LOW"
                    ),

                "description":
                    rule_data.get(
                        "description",
                        ""
                    ),

                "mitre_tactic":
                    rule_data.get(
                        "mitre_tactic",
                        ""
                    ),

                "mitre_technique":
                    rule_data.get(
                        "mitre_technique",
                        ""
                    )
            })

    return normalized

# =========================================
# LOAD JSON RULES
# =========================================

def load_json_rules(file_path, rule_type):

    with open(file_path, "r") as file:

        rules = json.load(file)

    normalized_rules = normalize_rules(

        rules,
        rule_type
    )

    for rule in normalized_rules:

        insert_rule(rule)

# =========================================
# LOAD DEFAULT RULES
# =========================================

def load_default_rules():

    existing_hids = fetch_rules("HIDS")

    existing_nids = fetch_rules("NIDS")

    if existing_hids and existing_nids:

        return

    load_json_rules(

        HIDS_RULES_FILE,
        "HIDS"
    )

    load_json_rules(

        NIDS_RULES_FILE,
        "NIDS"
    )