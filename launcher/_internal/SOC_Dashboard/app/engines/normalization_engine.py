from datetime import datetime


def normalize_event(
    source,
    event_id,
    description,
    raw_log,
    severity="INFO",
    category="Other",
    computer="",
    user="",
    process_name="",
    ip_address="",
    log_type="HIDS"
):

    return {

        "timestamp":
            raw_log.get("timestamp")
            if isinstance(raw_log, dict)
            and raw_log.get("timestamp")
            else datetime.now().isoformat(),

        "source":
            source,

        "event_id":
            str(event_id),

        "description":
            description,

        "raw_data":
            raw_log,

        "severity":
            severity,

        "category":
            category,

        "computer":
            computer,

        "user":
            user,

        "process_name":
            process_name,

        "ip_address":
            ip_address,

        "log_type":
            log_type
    }