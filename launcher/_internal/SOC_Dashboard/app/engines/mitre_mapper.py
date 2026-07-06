MITRE_RULES={

    "powershell":{

        "technique":"T1059",

        "name":
        "Command and Scripting Interpreter",

        "tactic":"Execution"
    },

    "cmd":{

        "technique":"T1059",

        "name":
        "Command Shell",

        "tactic":"Execution"
    },

    "brute force":{

        "technique":"T1110",

        "name":
        "Brute Force",

        "tactic":"Credential Access"
    },

    "credential":{

        "technique":"T1003",

        "name":
        "Credential Dumping",

        "tactic":"Credential Access"
    },

    "mimikatz":{

        "technique":"T1003",

        "name":
        "Credential Dumping",

        "tactic":"Credential Access"
    },

    "registry":{

        "technique":"T1547",

        "name":
        "Registry Run Keys",

        "tactic":"Persistence"
    },

    "scheduled task":{

        "technique":"T1053",

        "name":
        "Scheduled Task",

        "tactic":"Persistence"
    },

    "service":{

        "technique":"T1543",

        "name":
        "Create or Modify System Process",

        "tactic":"Persistence"
    },

    "wmi":{

        "technique":"T1047",

        "name":
        "Windows Management Instrumentation",

        "tactic":"Execution"
    },

    "dns":{

        "technique":"T1071",

        "name":
        "Application Layer Protocol",

        "tactic":"Command and Control"
    },

    "smb":{

        "technique":"T1021",

        "name":
        "Remote Services",

        "tactic":"Lateral Movement"
    },

    "rdp":{

        "technique":"T1021",

        "name":
        "Remote Desktop Protocol",

        "tactic":"Lateral Movement"
    },

    "defender":{

        "technique":"T1562",

        "name":
        "Impair Defenses",

        "tactic":"Defense Evasion"
    },

    "ransomware":{

        "technique":"T1486",

        "name":
        "Data Encrypted for Impact",

        "tactic":"Impact"
    }
}


def map_mitre(alert):

    text=" ".join(map(str,[

        alert.get("type",""),
        alert.get("description",""),
        alert.get("category","")

    ])).lower()

    for k,v in MITRE_RULES.items():

        if k in text:

            alert["mitre_technique"]=v["technique"]

            alert["mitre_name"]=v["name"]

            alert["mitre_tactic"]=v["tactic"]

            return alert

    alert["mitre_technique"]="T0000"
    alert["mitre_name"]="Unknown"
    alert["mitre_tactic"]="Unknown"

    return alert