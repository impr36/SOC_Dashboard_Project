import pandas as pd

from app.collectors.sysmon_collector import (
    read_sysmon_logs
)

from app.collectors.security_collector import (
    read_security_logs
)

from app.collectors.system_collector import (
    read_system_logs
)

from app.collectors.application_collector import (
    read_application_logs
)

from app.collectors.powershell_collector import (
    read_powershell_logs
)

from app.collectors.network_collector import (
    read_network_logs
)

from app.collectors.firewall_collector import (
    read_firewall_logs
)

from app.collectors.dns_collector import (
    read_dns_logs
)

from app.collectors.defender_collector import (
    read_defender_logs
)

from app.collectors.registry_collector import (
    read_registry_logs
)

from app.collectors.taskscheduler_collector import (
    read_taskscheduler_logs
)

from app.collectors.wmi_collector import (
    read_wmi_logs
)


def collect_all_logs(hours=720):

    print("\n[1] Collecting System Logs...")

    all_logs=[]

    collectors=[

        # ================= CORE WINDOWS =================
    
        read_sysmon_logs,
        read_security_logs,
        read_system_logs,
        read_application_logs,
        read_powershell_logs,
    
        # ================= NETWORK =================
    
        read_network_logs,
        read_firewall_logs,
        read_dns_logs,
    
        # ================= DEFENDER =================
    
        read_defender_logs,
    
        # ================= PERSISTENCE =================
    
        read_registry_logs,
        read_taskscheduler_logs,
        read_wmi_logs
    ]

    for collector in collectors:

        try:

            logs=collector(hours=hours)

            if isinstance(logs,pd.DataFrame):

                if not logs.empty:

                    all_logs.append(logs)

                    print(
                        f"[SOC] "
                        f"{collector.__name__}: "
                        f"{len(logs)} logs"
                    )

        except Exception as e:

            print(
                f"[SOC ERROR] "
                f"{collector.__name__}: {e}"
            )

    if not all_logs:

        return pd.DataFrame()

    return pd.concat(
        all_logs,
        ignore_index=True
    )