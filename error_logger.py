import csv
import os
import re
from datetime import datetime

from output_sanitizer import redact_secrets

LOG_FILE = "compiler_errors.csv"


def initialize_log_file():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Error_Type", "Line_Number", "Raw_Message", "Source_Code_Snippet"])


def parse_gcc_error(raw_error_text):
    pattern = r"(?:main|candidate|temp_code|temp_source)\.cpp:(\d+):(\d+):\s+(error|warning):\s+(.*)"
    match = re.search(pattern, raw_error_text or "")
    if match:
        return match.group(1), match.group(3), match.group(4)
    return "Unknown", "Error", (raw_error_text or "")[:300]


def log_error(raw_error_text, user_code):
    initialize_log_file()
    line_num, _severity, clean_message = parse_gcc_error(raw_error_text)
    code_lines = (user_code or "").split("\n")
    try:
        failed_line_index = int(line_num) - 1
        source_snippet = (
            code_lines[failed_line_index].strip()
            if 0 <= failed_line_index < len(code_lines)
            else "N/A"
        )
    except ValueError:
        source_snippet = "N/A"

    with open(LOG_FILE, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow(
            [
                timestamp,
                redact_secrets(clean_message)[:300],
                line_num,
                redact_secrets(raw_error_text or "")[:500],
                redact_secrets(source_snippet)[:200],
            ]
        )
    return clean_message
