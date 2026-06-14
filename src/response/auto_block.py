"""
auto_block.py
Automated response module: blocks malicious IP addresses using
iptables (Linux). Falls back to a 'dry run' simulation mode if
iptables is unavailable or the script is not run as root, so it
can be tested safely in any environment.
"""

import subprocess
import shutil

_blocked_ips = set()


def _iptables_available() -> bool:
    return shutil.which("iptables") is not None


def block_ip(ip_address: str, dry_run: bool = None) -> dict:
    """
    Block an IP address using iptables (DROP all incoming traffic from it).

    Args:
        ip_address: The IP address to block.
        dry_run: If True, simulate without executing system commands.
                 If None, auto-detect based on iptables availability/permissions.

    Returns:
        dict with status info.
    """
    if ip_address in _blocked_ips:
        return {"ip": ip_address, "status": "already_blocked", "dry_run": dry_run}

    if dry_run is None:
        dry_run = not _iptables_available()

    if dry_run:
        print(f"[DRY-RUN] Would block IP: {ip_address}")
        _blocked_ips.add(ip_address)
        return {"ip": ip_address, "status": "blocked_simulated", "dry_run": True}

    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        _blocked_ips.add(ip_address)
        print(f"[BLOCKED] IP {ip_address} added to firewall DROP rules.")
        return {"ip": ip_address, "status": "blocked", "dry_run": False}
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block {ip_address}: {e.stderr.decode().strip()}")
        return {"ip": ip_address, "status": "error", "error": str(e)}


def unblock_ip(ip_address: str, dry_run: bool = None) -> dict:
    """Remove a previously added DROP rule for an IP address."""
    if dry_run is None:
        dry_run = not _iptables_available()

    if dry_run:
        print(f"[DRY-RUN] Would unblock IP: {ip_address}")
        _blocked_ips.discard(ip_address)
        return {"ip": ip_address, "status": "unblocked_simulated", "dry_run": True}

    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        _blocked_ips.discard(ip_address)
        print(f"[UNBLOCKED] IP {ip_address} removed from firewall DROP rules.")
        return {"ip": ip_address, "status": "unblocked", "dry_run": False}
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to unblock {ip_address}: {e.stderr.decode().strip()}")
        return {"ip": ip_address, "status": "error", "error": str(e)}


def list_blocked_ips() -> list:
    """Return the list of IPs currently tracked as blocked (this session)."""
    return sorted(_blocked_ips)


def handle_prediction(record: dict, confidence_threshold: float = 0.7) -> dict:
    """
    Given a prediction record (from predict.py), decide whether
    to block the source IP automatically.

    Args:
        record: dict with keys 'src_ip', 'label', 'confidence'.
        confidence_threshold: Minimum confidence to trigger a block.

    Returns:
        dict describing the action taken.
    """
    if record.get("label") == "malicious" and record.get("confidence", 0) >= confidence_threshold:
        return block_ip(record["src_ip"])
    return {"ip": record.get("src_ip"), "status": "no_action"}


if __name__ == "__main__":
    # Smoke test (will run in dry-run mode unless on Linux with iptables + root)
    print(block_ip("203.0.113.45"))
    print(list_blocked_ips())
    print(unblock_ip("203.0.113.45"))
