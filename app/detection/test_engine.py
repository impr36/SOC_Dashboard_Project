import random

from app.alerts.alert_manager import create_alert


TEST_ALERTS = [

    {
        "alert_type": "Port Scan",
        "severity": "HIGH",
        "category": "Reconnaissance",
        "source": "192.168.1.10",
        "description": "Multiple ports scanned"
    },

    {
        "alert_type": "Failed Login Attempts",
        "severity": "MEDIUM",
        "category": "Authentication",
        "source": "WIN-USER01",
        "description": "Excessive failed logins detected"
    },

    {
        "alert_type": "PowerShell Execution",
        "severity": "HIGH",
        "category": "Execution",
        "source": "WIN-ADMIN",
        "description": "Suspicious PowerShell command executed"
    },

    {
        "alert_type": "Ransomware Activity",
        "severity": "CRITICAL",
        "category": "Impact",
        "source": "WIN-SERVER01",
        "description": "Mass file encryption behavior detected"
    }

]


def run_fake_scan():

    total_alerts = random.randint(5, 15)

    for _ in range(total_alerts):

        alert = random.choice(TEST_ALERTS)

        create_alert(

            alert_type=alert["alert_type"],
            severity=alert["severity"],
            category=alert["category"],
            source=alert["source"],
            description=alert["description"]

        )

    return {

        "status": "success",
        "alerts_generated": total_alerts
    }