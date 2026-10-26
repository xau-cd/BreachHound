"""Web attack signatures and payload normalisation.

Detection model
---------------
1. The request target, User-Agent and Referer are *normalised*: repeated URL decoding
   (up to 4 passes), HTML entities, ``\\xHH`` escapes, NUL removal, Unicode NFKC, lowercase,
   backslash -> slash, SQL comment stripping, whitespace collapsing and Log4j lookup
   de-obfuscation.
2. Signatures run on the normalised text. A cheap trigger pre-filter skips benign lines.

Known limits (see docs/detectors.md): signatures detect *attempts*, not success; custom
encodings (base64/hex-wrapped payloads), payloads in POST bodies and fragmented requests are
invisible to an access log.
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote_plus

from breachhound.core.constants import EXPLOIT_TOOL_USER_AGENTS, SCANNER_USER_AGENTS
from breachhound.core.enums import Category, Severity
from breachhound.detectors.web.parser import WebLogEntry

_MAX_DECODE_PASSES = 4
_NEEDS_DECODE = re.compile(r"[%&\\+]")
_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_VERSION_COMMENT = re.compile(r"/\*!\d*(.*?)\*/")
_COMMENT = re.compile(r"/\*.*?\*/")
_WS = re.compile(r"\s+")
_LOOKUP = re.compile(r"\$\{(?:lower:|upper:|::-|[a-z]{0,10}:-)([^}$]{0,8})\}")


@dataclass(frozen=True)
class NormalizedText:
    decoded: str  # decoded + lowercase, comments kept
    normalized: str  # decoded + comments stripped + slashes + de-obfuscation
    layers: int  # number of decoding passes that changed the text


def normalize_payload(value: str) -> NormalizedText:
    """Normalise a raw log field before signature matching."""
    text = value
    layers = 0
    for _ in range(_MAX_DECODE_PASSES):
        if not _NEEDS_DECODE.search(text):
            break
        decoded = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
        decoded = html.unescape(unquote_plus(decoded, errors="replace"))
        if decoded == text:
            break
        text = decoded
        layers += 1
    text = text.replace("\x00", "")
    if not text.isascii():
        text = unicodedata.normalize("NFKC", text)
    decoded_view = _WS.sub(" ", text.lower())
    stripped = _COMMENT.sub(" ", _VERSION_COMMENT.sub(r" \1 ", decoded_view))
    for _ in range(3):  # nested ${lower:j}ndi lookups
        replaced = _LOOKUP.sub(r"\1", stripped)
        if replaced == stripped:
            break
        stripped = replaced
    normalized = _WS.sub(" ", stripped.replace("\\", "/"))
    return NormalizedText(decoded=decoded_view, normalized=normalized, layers=layers)


@dataclass(frozen=True)
class Rule:
    id: str
    category: Category
    severity: Severity
    confidence: float
    title: str
    pattern: re.Pattern[str]
    view: str = "normalized"
    fields: tuple[str, ...] = ("target", "user_agent", "referer")


@dataclass(frozen=True)
class RuleMatch:
    rule: Rule
    field: str
    snippet: str
    layers: int


_ALL = ("target", "user_agent", "referer")
_TARGET = ("target",)
_S = Severity
_C = Category


def _r(
    rid: str,
    cat: Category,
    sev: Severity,
    conf: float,
    title: str,
    pattern: str,
    *,
    view: str = "normalized",
    fields: tuple[str, ...] = _ALL,
) -> Rule:
    return Rule(rid, cat, sev, conf, title, re.compile(pattern), view, fields)


RULES: tuple[Rule, ...] = (
    # --- SQL injection ------------------------------------------------------------
    _r("SQLI-UNION", _C.SQL_INJECTION, _S.HIGH, 0.90, "SQL injection: UNION SELECT",
       r"\bunion(?:\s+all|\s+distinct)?\s+select\b"),
    _r("SQLI-TAUTOLOGY", _C.SQL_INJECTION, _S.HIGH, 0.85, "SQL injection: tautology (OR 1=1)",
       r"\b(?:or|and)\s+(?:(\d+)\s*=\s*\1|([\x27\x22])([^\x27\x22]*)\2\s*=\s*\2\3)(?=\W|$)"),
    _r("SQLI-BOOLEAN", _C.SQL_INJECTION, _S.MEDIUM, 0.55, "SQL injection: boolean condition",
       r"\b(?:or|and)\s+\d+\s*(?:=|<>|!=|<|>)\s*\d+(?=\W|$)"),
    _r("SQLI-COMMENT", _C.SQL_INJECTION, _S.MEDIUM, 0.65, "SQL injection: comment terminator",
       r"(?:[\x27\x22)]|;)\s*(?:--(?:\s|$)|#|/\*)", view="decoded", fields=_TARGET),
    _r("SQLI-STACKED", _C.SQL_INJECTION, _S.HIGH, 0.80, "SQL injection: stacked query",
       r";\s*(?:drop|insert|update|delete|alter|create|truncate|exec|execute|shutdown|select|declare)\b(?!\s*=)",
       fields=_TARGET),
    _r("SQLI-FUNC", _C.SQL_INJECTION, _S.HIGH, 0.80, "SQL injection: database function/metadata",
       r"\b(?:sleep|benchmark|pg_sleep|load_file|extractvalue|updatexml|group_concat|concat_ws)\s*\("
       r"|\bwaitfor\s+delay\b|\binto\s+(?:out|dump)file\b|\binformation_schema\b|\bxp_cmdshell\b"
       r"|@@version|\bdatabase\s*\(\s*\)|\bchar\s*\(\s*\d+(?:\s*,\s*\d+)+\s*\)"
       r"|\b(?:select|union)\b.{0,60}\bfrom\b.{0,40}\b(?:users|mysql\.user|pg_user|sqlite_master)\b"),
    # --- XSS ------------------------------------------------------------------------
    _r("XSS-SCRIPT", _C.XSS, _S.HIGH, 0.92, "XSS: <script> tag", r"<\s*/?\s*script\b"),
    _r("XSS-EVENT", _C.XSS, _S.HIGH, 0.80, "XSS: HTML event handler",
       r"\bon(?:error|load|click|mouse(?:over|enter|move|out)|focus|blur|submit|toggle|begin|"
       r"start|finish|animationstart|pointerover|input|change|key(?:down|up|press))\s*="),
    _r("XSS-JSURI", _C.XSS, _S.MEDIUM, 0.70, "XSS: javascript:/data: URI",
       r"\b(?:javascript|vbscript)\s*:|data\s*:\s*text/html"),
    _r("XSS-TAG", _C.XSS, _S.MEDIUM, 0.60, "XSS: injected HTML element",
       r"<\s*(?:iframe|svg|img|object|embed|body|video|audio|details|math|marquee|style|base)\b"),
    _r("XSS-DOM", _C.XSS, _S.MEDIUM, 0.55, "XSS: DOM/JS sink",
       r"document\s*\.\s*(?:cookie|location|write|domain)|\bwindow\s*\.\s*location|\bfromcharcode\b"
       r"|\b(?:alert|prompt|confirm)\s*\("),
    # --- Path traversal ----------------------------------------------------------------
    _r("TRAV-DOTDOT", _C.PATH_TRAVERSAL, _S.MEDIUM, 0.60, "Path traversal: ../ sequence",
       r"\.\.+/|\.\.;/|/\.\.(?:$|\?)|\.\.\ufffd+", fields=_TARGET),
    _r("TRAV-SENSITIVE", _C.PATH_TRAVERSAL, _S.HIGH, 0.95, "Path traversal: sensitive system file",
       r"(?:^|/)etc/(?:passwd|shadow|group|gshadow|hosts|sudoers|issue|crontab|fstab|ssh/sshd_config)\b"
       r"|/proc/self/(?:environ|cmdline|maps|fd)|(?:^|/)root/\.(?:ssh|bash_history)"
       r"|\.ssh/(?:id_rsa|authorized_keys)|\bboot\.ini\b|\bwin\.ini\b"
       r"|(?:^|/)(?:windows|winnt)/(?:system32|system\.ini|win\.ini)|\bc:/(?:windows|boot)"
       r"|/var/log/(?:auth|syslog|apache2?|nginx)", fields=_TARGET),
    # --- Remote code / command execution --------------------------------------------------
    _r("RCE-CMDCHAIN", _C.REMOTE_CODE_EXECUTION, _S.HIGH, 0.85, "Command injection: shell command chained",
       r"(?:;|\|\|?|&&|\x60|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|netcat|bash|sh|zsh|"
       r"python[23]?|perl|php|ruby|powershell|cmd(?:\.exe)?|chmod|chown|rm|echo|ping|nslookup|dig|"
       r"busybox|tftp|ftp|telnet|sleep|env|ifconfig|ipconfig|netstat|tar|base64|mkfifo|certutil|"
       r"bitsadmin)(?=\s|$|[;|&)\x60\x27\x22<>/$])"),
    _r("RCE-SHELLPATH", _C.REMOTE_CODE_EXECUTION, _S.HIGH, 0.88, "Command execution: shell/interpreter path",
       r"/bin/(?:ba|z|da|k)?sh\b|/usr/bin/(?:env|python[23]?|perl|php|nc|wget|curl)\b"
       r"|\bcmd(?:\.exe)?\s*/c\b|\bpowershell(?:\.exe)?\s+-|/dev/tcp/|\bnc\s+-[a-z]*e\b|\bbash\s+-i\b"),
    _r("RCE-FUNC", _C.REMOTE_CODE_EXECUTION, _S.HIGH, 0.75, "Code execution: dangerous function call",
       r"\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|call_user_func"
       r"(?:_array)?|create_function|base64_decode|gzinflate|str_rot13)\s*\("),
    _r("RCE-WRAPPER", _C.REMOTE_CODE_EXECUTION, _S.HIGH, 0.85, "Code execution: PHP wrapper / ini override",
       r"\b(?:php|expect|phar|zip|data|glob|input)://|\ballow_url_include\b|\bauto_prepend_file\b"),
    _r("RCE-SHELLSHOCK", _C.REMOTE_CODE_EXECUTION, _S.CRITICAL, 0.92, "Shellshock-style function definition",
       r"\(\s*\)\s*\{[^}]*\}\s*;"),
    _r("RCE-LOG4J", _C.REMOTE_CODE_EXECUTION, _S.CRITICAL, 0.93, "Log4Shell JNDI lookup",
       r"\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http|https|nis|corba)"),
    _r("RCE-SPRING4SHELL", _C.REMOTE_CODE_EXECUTION, _S.CRITICAL, 0.90, "Spring4Shell class loader access",
       r"class\.module\.classloader", fields=_TARGET),
    _r("RCE-PARAM", _C.REMOTE_CODE_EXECUTION, _S.MEDIUM, 0.55, "Command-like request parameter",
       r"[?&](?:cmd|command|exec|execute|shell|run)=[^&\s]+", fields=_TARGET),
    # --- Web shells / uploads / recon ----------------------------------------------------------
    _r("WEB-UPLOAD-EXEC", _C.WEBSHELL_ACCESS, _S.HIGH, 0.70, "Request to an executable script in an upload directory",
       r"/(?:uploads?|files?|images?|media|tmp|attachments?|userfiles|wp-content/uploads)/[^?#]*"
       r"\.(?:php\d?|phtml|phar|pht|jsp|jspx|asp|aspx|ashx|cgi|pl|py)(?:$|[?/])", fields=_TARGET),
    _r("WEB-SHELLNAME", _C.WEBSHELL_ACCESS, _S.MEDIUM, 0.60, "Request to a well-known web shell name",
       r"(?:^|/)(?:c99|r57|b374k|wso\d*|alfa|webshell|backdoor|cmd|shell|indoxploit|filesman)"
       r"\.(?:php\d?|phtml|asp|aspx|jsp)(?:$|\?)", fields=_TARGET),
    _r("RECON-SENSITIVE", _C.RECON, _S.LOW, 0.50, "Probe for sensitive/configuration file",
       r"(?:^|/)(?:\.env(?:\.\w+)?|\.git/(?:config|head)|\.svn/entries|\.htpasswd|\.htaccess|"
       r"wp-config\.php(?:\.\w+|~)?|web\.config|config\.php\.(?:bak|old|save)|database\.sql|dump\.sql|"
       r"backup\.(?:zip|tar\.gz|sql)|phpinfo\.php|id_rsa)(?=$|\?|/)", fields=_TARGET),
    _r("SCAN-UA", _C.SCANNER, _S.LOW, 0.85, "Known scanner User-Agent",
       rf"(?:{SCANNER_USER_AGENTS})", fields=("user_agent",)),
    _r("SCAN-EXPLOIT-UA", _C.SCANNER, _S.MEDIUM, 0.90, "Known exploitation tool User-Agent",
       rf"(?:{EXPLOIT_TOOL_USER_AGENTS})", fields=("user_agent",)),
)  # fmt: skip

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in RULES}

# Cheap pre-filter: lines containing none of these tokens cannot match any signature.
_TRIGGER = re.compile(
    r"union|select|[<>\x27\x22`;|$(){}@]|\.\.|etc/|proc/|cmd|exec|eval|system|script|on[a-z]+\s*=|"
    r"sleep|benchmark|--|#|/\*|://|\.ph|\.asp|\.jsp|upload|\.env|\.git|\.svn|/bin/|win\.ini|boot\.ini|"
    r"jndi|class\.module|information_schema|\bor\b|\band\b|nikto|nmap|masscan|dirbuster|gobuster|"
    r"wpscan|nuclei|acunetix|nessus|zgrab|wfuzz|ffuf|feroxbuster|openvas|w3af|burp|sqlmap|havij|"
    r"hydra|metasploit|commix|sqlninja|wp-config|web\.config|\.htpasswd|\.htaccess|backup|dump|"
    r"id_rsa|phpinfo|shell|c99|r57|b374k|wso|alfa|backdoor|filesman|indoxploit|php|input|expect|"
    r"document|window|alert|prompt|confirm|fromcharcode|data\s*:|vbscript|javascript|waitfor|outfile|dumpfile|"
    r"load_file|extractvalue|updatexml|group_concat|concat_ws|char\s*\(|database|@@version"
)


def scan_entry(entry: WebLogEntry) -> list[RuleMatch]:
    """Run every signature on the entry's target, User-Agent and Referer."""
    matches: list[RuleMatch] = []
    values = {
        "target": entry.target,
        "user_agent": entry.user_agent or "",
        "referer": entry.referer or "",
    }
    for field_name, value in values.items():
        if not value:
            continue
        views = normalize_payload(value)
        if not _TRIGGER.search(views.normalized) and not _TRIGGER.search(views.decoded):
            continue
        for rule in RULES:
            if field_name not in rule.fields:
                continue
            text = views.decoded if rule.view == "decoded" else views.normalized
            found = rule.pattern.search(text)
            if found:
                matches.append(RuleMatch(rule, field_name, found.group(0)[:200], views.layers))
    return matches
