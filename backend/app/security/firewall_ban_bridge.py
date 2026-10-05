"""
Firewall Ban Bridge — Infrastructure-Level IP Enforcement

Provides programmatic ban/unban at the OS firewall level.
- Linux: Uses Fail2Ban's client socket interface (fail2ban-client)
- Windows: Uses netsh advfirewall for Windows Firewall rules
- Fallback: Dry-run mode for environments without firewall access

Ban escalation: repeat offenses from the same actor cluster escalate
ban duration (linked to attacker_profiler actor-cluster attribution).

This is infrastructure-level enforcement LAYERED ON TOP of GhostPrompt's
existing application-layer blocking — not replacing it.
"""

import asyncio
import platform
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.core.logging import get_logger

logger = get_logger("security.firewall_ban")


# ── Ban Escalation Configuration ──
BASE_BAN_DURATION_SECONDS = 300       # 5 minutes initial ban
ESCALATION_MULTIPLIER = 3.0          # Each repeat → 3x longer
MAX_BAN_DURATION_SECONDS = 86400     # 24 hour maximum
DEFAULT_TRIGGER_THRESHOLD = 3        # N CRITICAL detections → auto-ban
OFFENSE_WINDOW_SECONDS = 3600        # Rolling 1-hour window


@dataclass
class BanRecord:
    """Active or historical ban record."""
    ip: str
    ban_id: str = ""
    reason: str = ""
    severity: str = "high"
    actor_cluster_id: str | None = None
    offense_count: int = 1
    ban_duration_seconds: int = BASE_BAN_DURATION_SECONDS
    banned_at: str = ""
    expires_at: str = ""
    is_active: bool = True
    ban_method: str = ""  # fail2ban, netsh, dry_run
    auto_banned: bool = True
    manually_unbanned: bool = False


# ── In-memory tracking (production: use Redis) ──
_active_bans: dict[str, BanRecord] = {}
_offense_history: dict[str, list[float]] = defaultdict(list)  # IP → list of offense timestamps
_actor_ban_count: dict[str, int] = defaultdict(int)  # actor_cluster_id → ban count


def _detect_platform() -> str:
    """Detect which firewall backend is available."""
    system = platform.system().lower()
    if system == "linux":
        # Check if fail2ban-client is available
        try:
            result = subprocess.run(
                ["fail2ban-client", "status"],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                return "fail2ban"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        # Fall back to iptables
        try:
            result = subprocess.run(
                ["iptables", "--version"],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                return "iptables"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    elif system == "windows":
        # Check if we have admin privileges for netsh
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                return "netsh"
        except Exception:
            pass
        # Non-admin: use dry_run (netsh requires elevation)
        return "dry_run"

    return "dry_run"


PLATFORM_BACKEND = _detect_platform()


class FirewallBanBridge:
    """Programmatic IP ban/unban at the OS firewall level."""

    def __init__(self):
        self.backend = PLATFORM_BACKEND
        logger.info("firewall_ban_bridge_initialized", backend=self.backend)

    async def should_ban(
        self,
        ip: str,
        severity: str,
        *,
        actor_cluster_id: str | None = None,
        threshold: int = DEFAULT_TRIGGER_THRESHOLD,
    ) -> bool:
        """
        Check if an IP should be auto-banned based on offense accumulation.
        Returns True if the IP has accumulated enough offenses in the window.
        """
        if severity not in ("critical", "high"):
            return False

        if ip in _active_bans and _active_bans[ip].is_active:
            return False  # Already banned

        now = time.time()
        _offense_history[ip] = [
            t for t in _offense_history[ip]
            if now - t < OFFENSE_WINDOW_SECONDS
        ]
        _offense_history[ip].append(now)

        # Also check actor cluster — even across IP rotation
        if actor_cluster_id:
            cluster_key = f"cluster:{actor_cluster_id}"
            _offense_history[cluster_key] = [
                t for t in _offense_history[cluster_key]
                if now - t < OFFENSE_WINDOW_SECONDS
            ]
            _offense_history[cluster_key].append(now)

            # If the same actor cluster has been banned before, lower threshold
            prior_bans = _actor_ban_count.get(actor_cluster_id, 0)
            effective_threshold = max(1, threshold - prior_bans)

            if len(_offense_history[cluster_key]) >= effective_threshold:
                return True

        return len(_offense_history[ip]) >= threshold

    async def ban_ip(
        self,
        ip: str,
        *,
        reason: str = "Automated ban — repeated critical detections",
        severity: str = "high",
        actor_cluster_id: str | None = None,
    ) -> BanRecord:
        """
        Ban an IP at the infrastructure firewall level.
        Ban duration escalates on repeat offenses.
        """
        # Calculate escalated ban duration
        prior_bans = 0
        if actor_cluster_id:
            prior_bans = _actor_ban_count.get(actor_cluster_id, 0)
            _actor_ban_count[actor_cluster_id] = prior_bans + 1
        elif ip in _active_bans:
            prior_bans = _active_bans[ip].offense_count

        duration = min(
            int(BASE_BAN_DURATION_SECONDS * (ESCALATION_MULTIPLIER ** prior_bans)),
            MAX_BAN_DURATION_SECONDS,
        )

        now = datetime.now(timezone.utc)
        ban_record = BanRecord(
            ip=ip,
            ban_id=f"ban-{ip}-{int(now.timestamp())}",
            reason=reason,
            severity=severity,
            actor_cluster_id=actor_cluster_id,
            offense_count=prior_bans + 1,
            ban_duration_seconds=duration,
            banned_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=duration)).isoformat(),
            is_active=True,
            ban_method=self.backend,
            auto_banned=True,
        )

        # Execute the actual firewall ban
        success = await self._execute_ban(ip, duration)
        if not success:
            ban_record.ban_method = "dry_run"
            logger.warning("firewall_ban_failed_fallback_dry_run", ip=ip)

        _active_bans[ip] = ban_record
        logger.info(
            "ip_banned",
            ip=ip,
            duration_seconds=duration,
            offense_count=prior_bans + 1,
            backend=ban_record.ban_method,
            actor_cluster=actor_cluster_id,
        )
        return ban_record

    async def unban_ip(self, ip: str, *, manual: bool = False) -> BanRecord | None:
        """
        Unban an IP — either manually by an analyst or on expiry.
        """
        ban = _active_bans.get(ip)
        if not ban or not ban.is_active:
            return None

        success = await self._execute_unban(ip)
        ban.is_active = False
        ban.manually_unbanned = manual

        logger.info("ip_unbanned", ip=ip, manual=manual, backend=self.backend)
        return ban

    async def get_active_bans(self) -> list[dict]:
        """Get all currently active bans."""
        now = datetime.now(timezone.utc)
        active = []
        expired_ips = []

        for ip, ban in _active_bans.items():
            if not ban.is_active:
                continue
            # Check expiry
            try:
                expires = datetime.fromisoformat(ban.expires_at)
                if now > expires:
                    expired_ips.append(ip)
                    continue
            except (ValueError, TypeError):
                pass

            active.append({
                "ip": ban.ip,
                "ban_id": ban.ban_id,
                "reason": ban.reason,
                "severity": ban.severity,
                "actor_cluster_id": ban.actor_cluster_id,
                "offense_count": ban.offense_count,
                "ban_duration_seconds": ban.ban_duration_seconds,
                "banned_at": ban.banned_at,
                "expires_at": ban.expires_at,
                "ban_method": ban.ban_method,
                "auto_banned": ban.auto_banned,
            })

        # Auto-unban expired bans
        for ip in expired_ips:
            await self.unban_ip(ip, manual=False)

        return active

    # ── Platform-Specific Execution ──

    async def _execute_ban(self, ip: str, duration_seconds: int) -> bool:
        """Execute the ban on the OS firewall."""
        try:
            if self.backend == "fail2ban":
                return await self._fail2ban_ban(ip, duration_seconds)
            elif self.backend == "netsh":
                return await self._netsh_ban(ip)
            elif self.backend == "iptables":
                return await self._iptables_ban(ip)
            else:
                logger.info("dry_run_ban", ip=ip, duration=duration_seconds)
                return True  # Dry run always succeeds
        except Exception as e:
            logger.error("firewall_ban_execution_failed", ip=ip, error=str(e))
            return False

    async def _execute_unban(self, ip: str) -> bool:
        """Execute the unban on the OS firewall."""
        try:
            if self.backend == "fail2ban":
                return await self._fail2ban_unban(ip)
            elif self.backend == "netsh":
                return await self._netsh_unban(ip)
            elif self.backend == "iptables":
                return await self._iptables_unban(ip)
            else:
                logger.info("dry_run_unban", ip=ip)
                return True
        except Exception as e:
            logger.error("firewall_unban_execution_failed", ip=ip, error=str(e))
            return False

    # ── Fail2Ban (Linux) ──
    async def _fail2ban_ban(self, ip: str, duration: int) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "fail2ban-client", "set", "ghostprompt", "banip", ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode == 0

    async def _fail2ban_unban(self, ip: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "fail2ban-client", "set", "ghostprompt", "unbanip", ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode == 0

    # ── Windows Firewall (netsh) ──
    async def _netsh_ban(self, ip: str) -> bool:
        rule_name = f"GhostPrompt-Ban-{ip.replace('.', '_')}"
        proc = await asyncio.create_subprocess_exec(
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=block",
            f"remoteip={ip}",
            "protocol=any",
            "enable=yes",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode == 0

    async def _netsh_unban(self, ip: str) -> bool:
        rule_name = f"GhostPrompt-Ban-{ip.replace('.', '_')}"
        proc = await asyncio.create_subprocess_exec(
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode == 0

    # ── iptables (Linux fallback) ──
    async def _iptables_ban(self, ip: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", f"GhostPrompt-Ban-{ip}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode == 0

    async def _iptables_unban(self, ip: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", f"GhostPrompt-Ban-{ip}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode == 0


# Singleton
firewall_ban_bridge = FirewallBanBridge()
