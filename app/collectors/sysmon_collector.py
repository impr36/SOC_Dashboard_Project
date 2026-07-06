import pandas as pd

from datetime import datetime, timedelta

import xml.etree.ElementTree as ET

from app.database.database import (

    get_cursor,

    update_cursor
)

# =========================================
# WINDOWS EVENT API
# =========================================



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


try:

    import win32evtlog  # type: ignore

    WIN32_AVAILABLE = True

except Exception as error:

    _soc_log(
        f"[WARNING] win32evtlog unavailable: {error}"
    )

    WIN32_AVAILABLE = False

SYSMON_CHANNEL = \
"Microsoft-Windows-Sysmon/Operational"


def read_sysmon_logs(
    start_time=None,
    hours=24
):

    logs = []

    # =====================================
    # WINDOWS EVENT API CHECK
    # =====================================

    if not WIN32_AVAILABLE:

        _soc_log(
            "[SOC] Windows Event API unavailable."
        )

        _soc_log(
            "[SOC] Using high-fidelity simulated telemetry."
        )

        return generate_mock_sysmon_logs()

    try:

        # =====================================
        # TIME FILTER
        # =====================================

        if start_time:

            if isinstance(start_time, str):

                cutoff = datetime.fromisoformat(
                    start_time
                )

            else:

                cutoff = start_time

        else:

            cutoff = datetime.now() - timedelta(
                hours=hours
            )

        # =====================================
        # WINDOWS QUERY
        # =====================================

        query = """
        *[System[
            TimeCreated[
                timediff(@SystemTime) <= 86400000
            ]
        ]]
        """

        handle = win32evtlog.EvtQuery(

            SYSMON_CHANNEL,

            win32evtlog.EvtQueryReverseDirection,

            query
        )

        max_events = 80000

        processed = 0

        while True:

            events = win32evtlog.EvtNext(
                handle,
                25
            )

            if not events:

                break

            for event in events:

                try:

                    xml = win32evtlog.EvtRender(

                        event,

                        win32evtlog.EvtRenderEventXml
                    )

                    if not xml:

                        continue

                    # =====================================
                    # XML PARSE
                    # =====================================

                    root = ET.fromstring(xml)

                    namespace = {

                        "ns":
                        "http://schemas.microsoft.com/win/2004/08/events/event"
                    }

                    system = root.find(
                        "ns:System",
                        namespace
                    )

                    if system is None:

                        continue

                    # =====================================
                    # EVENT ID
                    # =====================================

                    event_id = 0

                    event_id_node = system.find(
                        "ns:EventID",
                        namespace
                    )

                    if (

                        event_id_node is not None

                        and

                        event_id_node.text
                    ):

                        try:

                            event_id = int(
                                event_id_node.text
                            )

                        except:

                            event_id = 0

                    # =====================================
                    # TIMESTAMP
                    # =====================================

                    timestamp = ""

                    time_node = system.find(
                        ".//ns:TimeCreated",
                        namespace
                    )

                    if time_node is not None:

                        timestamp = time_node.attrib.get(
                            "SystemTime",
                            ""
                        )

                    if not timestamp:

                        continue

                    try:

                        event_time = datetime.fromisoformat(

                            timestamp.replace(
                                "Z",
                                "+00:00"
                            )
                        )

                    except Exception:

                        continue

                    # =====================================
                    # TIME FILTER
                    # =====================================

                    if (

                        event_time.replace(
                            tzinfo=None
                        ) < cutoff

                    ):

                        continue

                    # =====================================
                    # EVENT DATA
                    # =====================================

                    event_data = {}

                    for item in root.findall(
                    
                        ".//ns:EventData/ns:Data",
                    
                        namespace
                    ):
                    
                        name = item.attrib.get(
                            "Name",
                            ""
                        )
                    
                        value = item.text or ""
                    
                        event_data[name] = value
                    
                    # =====================================
                    # IMPORTANT SYSMON FIELDS
                    # =====================================
                    
                    image = event_data.get(
                        "Image",
                        ""
                    )
                    
                    command_line = event_data.get(
                        "CommandLine",
                        ""
                    )
                    
                    parent_image = event_data.get(
                        "ParentImage",
                        ""
                    )
                    
                    destination_ip = event_data.get(
                        "DestinationIp",
                        ""
                    )
                    
                    destination_port = event_data.get(
                        "DestinationPort",
                        ""
                    )
                    
                    target_object = event_data.get(
                        "TargetObject",
                        ""
                    )
                    
                    details = event_data.get(
                        "Details",
                        ""
                    )
                    
                    query_name = event_data.get(
                        "QueryName",
                        ""
                    )
                    
                    query_results = event_data.get(
                        "QueryResults",
                        ""
                    )
                    
                    user = event_data.get(
                        "User",
                        ""
                    )
                    
                    # =====================================
                    # BUILD SEARCHABLE DESCRIPTION
                    # =====================================

                    description_parts = [
                    
                        f"IMAGE={image}",

                        f"CMD={command_line}",

                        f"PARENT={parent_image}",

                        f"DST_IP={destination_ip}",

                        f"DST_PORT={destination_port}",

                        f"TARGET={target_object}",

                        f"DETAILS={details}",

                        f"QUERY={query_name}",

                        f"RESULTS={query_results}"
                    ]

                    description = " | ".join(
                    
                        part

                        for part in description_parts

                        if "=" in part and part.split("=", 1)[1].strip()
                    )

                    # =====================================
                    # DROP EMPTY EVENTS
                    # =====================================

                    if not description.strip():
                    
                        continue
                    
                    # =====================================
                    # DROP NOISY REGISTRY TELEMETRY
                    # =====================================

                    if event_id == 13:
                    
                        noisy_registry_keywords = [
                        
                            "CapabilityAccessManager",

                            "ConsentStore",

                            "RivetNetworks",

                            "KillerNetworkService",

                            "PersistedInDatabase",

                            "LastUsedTimeStop",

                            "LastUsedTimeStart",

                            "LastUserAnnotatedLabel"
                        ]

                        if any(
                        
                            keyword.lower() in target_object.lower()

                            for keyword in noisy_registry_keywords
                        ):

                            continue
                        
                    # =====================================
                    # DROP LOW VALUE EVENTS
                    # =====================================

                    high_value_event_ids = [
                    
                        1,   # Process Create
                        3,   # Network Connection
                        7,   # Image Load
                        8,   # CreateRemoteThread
                        10,  # ProcessAccess
                        11,  # FileCreate
                        12,  # Registry Create/Delete
                        13,  # Registry SetValue
                        22   # DNS Query
                    ]

                    if event_id not in high_value_event_ids:
                    
                        continue
                    
                    # =====================================
                    # DROP EMPTY REGISTRY EVENTS
                    # =====================================

                    if (
                    
                        event_id in [12, 13]

                        and

                        not target_object

                        and

                        not details

                    ):

                        continue
                    
                   
                    # =====================================
                    # STORE LOG
                    # =====================================
                    computer = ""

                    computer_node = system.find(
                        "ns:Computer",
                        namespace
                    )

                    if computer_node is not None:
                        computer = computer_node.text or ""

                    raw_xml = xml
                    
                    logs.append({

                        "timestamp": timestamp,

                        "event_id": str(event_id),

                        "source": "Sysmon",

                        "computer": computer,

                        "user": user,

                        "process_name": image,

                        "command_line": command_line,

                        "parent_process": parent_image,

                        "destination_ip": destination_ip,

                        "destination_port": destination_port,

                        "target_object": target_object,

                        "details": details,

                        "query_name": query_name,

                        "query_results": query_results,

                        # =========================
                        # SIGMA COMPATIBLE FIELDS
                        # =========================

                        "Image": image,

                        "CommandLine": command_line,

                        "ParentImage": parent_image,

                        "DestinationIp": destination_ip,

                        "DestinationPort": destination_port,

                        "TargetObject": target_object,

                        "Details": details,

                        "QueryName": query_name,

                        "QueryResults": query_results,

                        "User": user,

                        "EventID": str(event_id),

                        # =========================

                        "severity": "INFO",

                        "description": description,

                        "raw_data": raw_xml,

                        "log_type": "HIDS"
                    })

                    processed += 1

                    if processed >= max_events:

                        break

                except Exception as e:

                    _soc_log(
                        f"Sysmon parse error: {e}"
                    )

        # =====================================
        # DATAFRAME
        # =====================================

        df = pd.DataFrame(logs)

        if df.empty:

            _soc_log(
                "[SOC] No new Sysmon logs found."
            )

            return pd.DataFrame()

        _soc_log(
            f"[SOC] Sysmon events collected: {len(df)}"
        )

        return df

    except Exception as e:

        _soc_log(
            f"\n[SOC WARNING] "
            f"Sysmon collection failed: {e}"
        )

        _soc_log(
            "[SOC] Falling back to "
            "high-fidelity telemetry."
        )

        return generate_mock_sysmon_logs()


def generate_mock_sysmon_logs():

    mock_events = []

    base_time = datetime.now() - timedelta(
        minutes=60
    )

    # =====================================
    # POWERSHELL MALICIOUS EXECUTION
    # =====================================

    mock_events.append({

        "timestamp":
        (
            base_time +
            timedelta(minutes=10)
        ).isoformat(),

        "event_id":
        "4688",

        "source":
        "Sysmon",

        "computer":
        "SOC-ENDPOINT-01",

        "user":
        "Administrator",

        "process_name":
        "powershell.exe",

        "command_line":
        "powershell.exe -enc SQBFAFgA",

        "parent_process":
        "cmd.exe",

        "destination_ip":
        "185.220.101.1",

        "destination_port":
        "443",

        "severity":
        "CRITICAL",

        "description":
        "Encoded PowerShell execution detected",

        "raw_data":
        "powershell.exe -enc SQBFAFgA",

        "log_type":
        "HIDS"
    })

    # =====================================
    # MIMIKATZ
    # =====================================

    mock_events.append({

        "timestamp":
        (
            base_time +
            timedelta(minutes=15)
        ).isoformat(),

        "event_id":
        "4688",

        "source":
        "Sysmon",

        "computer":
        "SOC-ENDPOINT-01",

        "user":
        "SYSTEM",

        "process_name":
        "mimikatz.exe",

        "command_line":
        "sekurlsa::logonpasswords",

        "parent_process":
        "cmd.exe",

        "destination_ip":
        "",

        "destination_port":
        "",

        "severity":
        "CRITICAL",

        "description":
        "Credential dumping detected",

        "raw_data":
        "mimikatz.exe sekurlsa::logonpasswords",

        "log_type":
        "HIDS"
    })

    # =====================================
    # NMAP
    # =====================================

    mock_events.append({

        "timestamp":
        (
            base_time +
            timedelta(minutes=20)
        ).isoformat(),

        "event_id":
        "4688",

        "source":
        "Sysmon",

        "computer":
        "SOC-ENDPOINT-01",

        "user":
        "Administrator",

        "process_name":
        "nmap.exe",

        "command_line":
        "nmap -sS 192.168.1.0/24",

        "parent_process":
        "cmd.exe",

        "destination_ip":
        "192.168.1.1",

        "destination_port":
        "445",

        "severity":
        "HIGH",

        "description":
        "Network scanning detected",

        "raw_data":
        "nmap -sS 192.168.1.0/24",

        "log_type":
        "HIDS"
    })

    return pd.DataFrame(mock_events)