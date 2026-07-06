import threading
import asyncio

from app.websocket_manager import manager

from app.collectors.collector_manager import (
    collect_all_logs
)

from app.engines.detection_engine import (
    detect_advanced_threats
)

from app.engines.grouping_engine import (
    group_alerts
)

from app.database.database import (
    insert_alert
)


class RealtimeMonitor:

    def __init__(self):

        self.running=False
        self.interval=15

    # =====================================
    # START
    # =====================================

    def start(self):

        if self.running:return

        self.running=True

        threading.Thread(

            target=lambda:
            asyncio.run(self.loop()),

            daemon=True

        ).start()

        print(
            "\n[SOC] Realtime monitor started\n"
        )

    # =====================================
    # STOP
    # =====================================

    def stop(self):

        self.running=False

    # =====================================
    # MAIN LOOP
    # =====================================

    async def loop(self):

        while self.running:

            try:

                print(
                    "[SOC] Collecting telemetry..."
                )

                logs=collect_all_logs(hours=1)

                if logs.empty:

                    print(
                        "[SOC] No new logs"
                    )

                    await asyncio.sleep(
                        self.interval
                    )

                    continue

                alerts=group_alerts(

                    detect_advanced_threats(
                        logs
                    )
                )

                inserted=sum(

                    insert_alert(a)

                    for a in alerts
                )

                print(

                    f"[SOC] "
                    f"Logs:{len(logs)} | "
                    f"Alerts:{inserted}"
                )

                if inserted:

                    await manager.broadcast({

                        "type":"NEW_ALERTS",

                        "count":inserted
                    })

            except Exception as e:

                print(
                    f"[SOC ERROR] {e}"
                )

            await asyncio.sleep(
                self.interval
            )