import socket

# port -> (service name, base risk level)
COMMON_PORTS = {
    21: ("FTP", "high"),
    22: ("SSH", "medium"),
    23: ("Telnet", "high"),
    25: ("SMTP", "medium"),
    53: ("DNS", "low"),
    80: ("HTTP", "low"),
    110: ("POP3", "medium"),
    143: ("IMAP", "medium"),
    443: ("HTTPS", "low"),
    445: ("SMB", "high"),
    3306: ("MySQL", "high"),
    3389: ("RDP", "high"),
    5432: ("PostgreSQL", "high"),
    8080: ("HTTP-Alt", "low"),
}


def scan_target(target: str, timeout: float = 1.0):
    """
    Attempts a TCP connection to each common port on the target.
    Returns a list of dicts describing any open ports found.
    """
    findings = []

    for port, (service, risk) in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                findings.append({
                    "port": port,
                    "service": service,
                    "risk_level": risk,
                    "description": f"Port {port} ({service}) is open and reachable."
                })
        except socket.gaierror:
            raise ValueError("Could not resolve target hostname.")
        finally:
            sock.close()

    return findings


def summarize_risk(findings: list) -> str:
    """Returns the highest risk level found, or 'none' if no open ports."""
    if not findings:
        return "none"

    risk_order = {"high": 3, "medium": 2, "low": 1}
    highest = max(findings, key=lambda f: risk_order.get(f["risk_level"], 0))
    return highest["risk_level"]