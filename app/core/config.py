# config.py
import platform
import os

APP_TITLE = "🛡️ SOC Simulator | Real + Simulated IDS"
APP_VERSION = "2.2 - Presentation Ready"
AUTHOR = "Pratyush Raj"

DB_NAME = "soc_simulator.db"
KEY_FILE = "encryption.key"
RULES_FILE = "detection_rules.json"
LOGS_DIR = "Forensic_Logs"

OS_TYPE = platform.system()
WINDOW_SIZE = "1520x940"
SIDEBAR_WIDTH = 260

CTK_APPEARANCE_MODE = "dark"
CTK_COLOR_THEME = "dark-blue"

# Configuration
USE_REAL_LOGS = True                    # Set False if real logs fail
DEFAULT_TIME_RANGE = "24h"