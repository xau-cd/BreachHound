"""Tunable defaults and static knowledge used by the detectors."""

from __future__ import annotations

DEFAULT_MAX_LINE_LENGTH = 8192
DEFAULT_MAX_LINES = 5_000_000
DEFAULT_MAX_FINDINGS = 50_000
DEFAULT_MAX_FILES = 200_000
DEFAULT_MAX_HASH_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_SCAN_BYTES = 1024 * 1024

DEFAULT_BRUTE_FORCE_THRESHOLD = 5
DEFAULT_BRUTE_FORCE_WINDOW = 300
DEFAULT_CONNECTION_BURST_THRESHOLD = 30
DEFAULT_CONNECTION_BURST_WINDOW = 60
DEFAULT_SLOW_BRUTE_FORCE_TOTAL = 20
DEFAULT_WEB_ERROR_BURST_THRESHOLD = 50
DEFAULT_WEB_ERROR_BURST_WINDOW = 60
DEFAULT_RECENT_DAYS = 7
DEFAULT_CORRELATION_WINDOW = 3600

EXCERPT_MAX = 500

DEFAULT_LLM_TIMEOUT = 60.0
DEFAULT_LLM_RETRIES = 2

UPLOAD_DIR_NAMES = frozenset(
    {
        "upload",
        "uploads",
        "files",
        "media",
        "tmp",
        "temp",
        "attachments",
        "userfiles",
        "user_uploads",
        "incoming",
    }
)

EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".php", ".php3", ".php4", ".php5", ".php7", ".pht", ".phtml", ".phar",
        ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cer", ".cfm", ".cgi",
        ".pl", ".py", ".sh",
    }
)  # fmt: skip

SCRIPT_EXTENSIONS = EXECUTABLE_EXTENSIONS | frozenset({".js", ".bat", ".ps1", ".rb"})

DATA_EXTENSIONS = frozenset(
    {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg",
        ".pdf", ".txt", ".csv", ".doc", ".docx", ".xls", ".xlsx", ".mp3",
        ".mp4", ".zip", ".css",
    }
)  # fmt: skip

BENIGN_HIDDEN_NAMES = frozenset(
    {".gitignore", ".gitattributes", ".gitkeep", ".keep", ".editorconfig", ".ds_store"}
)
BENIGN_HIDDEN_DIRS = frozenset({".well-known", ".github", ".git", ".vscode", ".idea"})

PRUNE_DIRS = frozenset({".git", "node_modules", "__pycache__", ".pytest_cache"})

SCANNER_USER_AGENTS = (
    "nikto|nmap|masscan|dirbuster|gobuster|wpscan|nuclei|acunetix|nessus|zgrab|"
    "wfuzz|ffuf|feroxbuster|openvas|w3af|burpcollaborator"
)
EXPLOIT_TOOL_USER_AGENTS = "sqlmap|havij|hydra|metasploit|commix|sqlninja"

PRIVILEGED_GROUPS = frozenset({"sudo", "wheel", "admin", "root", "adm", "docker", "lxd", "shadow"})
