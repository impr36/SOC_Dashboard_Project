import pandas as pd
import psutil
from datetime import datetime

from app.engines.normalization_engine import (
    normalize_event
)

SUSPICIOUS_PORTS = [

    4444,
    1337,
    5555,
    6666,
    31337
]

def determine_severity(port):

    if port in SUSPICIOUS_PORTS:

        return "HIGH"

    return "LOW"

def read_network_logs(hours=24):

    logs=[]

    try:

        connections=psutil.net_connections()

        for conn in connections:

            try:

                laddr = ""

                raddr = ""

                lport = ""

                rport = ""

                if conn.laddr:

                    laddr = conn.laddr.ip
                    lport = conn.laddr.port

                if conn.raddr:

                    raddr = conn.raddr.ip
                    rport = conn.raddr.port

                process_name = ""

                try:
                
                    if conn.pid:
                    
                        process_name = psutil.Process(
                            conn.pid
                        ).name()

                except:
                
                    process_name = str(conn.pid)

                description = (
                
                    f"Connection "

                    f"{laddr}:{lport} -> "

                    f"{raddr}:{rport} "

                    f"PID={conn.pid} "

                    f"PROCESS={process_name} "

                    f"STATUS={conn.status}"
                )

                logs.append(

                   normalize_event(
                                    
                        source="Network",
                    
                        event_id=1,
                    
                        description=description,
                    
                        raw_log=description,
                    
                        severity=
                        determine_severity(rport),
                    
                        category=
                        "Network",
                    
                        ip_address=raddr,
                    
                        process_name=process_name,
                    
                        user="",
                    
                        computer="",
                    
                        log_type="NIDS"
                    )
                )

            except:
                pass

        print(
            f"[NETWORK] "
            f"Connections collected: {len(logs)}"
        )

    except Exception as e:

        print(
            f"[NETWORK COLLECTOR ERROR] {e}"
        )

    return pd.DataFrame(logs)