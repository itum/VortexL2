"""
VortexL2 Port Forward Management

Handles socat-based TCP and UDP port forwarding with systemd service management.
Each port+protocol forward gets its own service file with the correct remote IP.
"""

import os
import subprocess
from pathlib import Path
from typing import List, Tuple, Dict, Optional


SYSTEMD_DIR = Path("/etc/systemd/system")

# One template per protocol; {port}, {remote_ip}
SERVICE_TEMPLATE_TCP = """[Unit]
Description=VortexL2 Port Forward - Port {port} (TCP)
After=network.target
Requires=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP4-LISTEN:{port},reuseaddr,fork TCP4:{remote_ip}:{port}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

SERVICE_TEMPLATE_UDP = """[Unit]
Description=VortexL2 Port Forward - Port {port} (UDP)
After=network.target
Requires=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat UDP4-LISTEN:{port},reuseaddr,fork UDP4:{remote_ip}:{port}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def run_command(cmd: str) -> Tuple[bool, str]:
    """Execute a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout.strip() or result.stderr.strip()
        return result.returncode == 0, output
    except Exception as e:
        return False, str(e)


def _parse_port_protocol(token: str) -> Optional[Tuple[int, str]]:
    """
    Parse a token like '443', '53/udp', '80/tcp'. Returns (port, protocol) or None if invalid.
    Protocol defaults to tcp; /udp (case-insensitive) means udp.
    """
    token = token.strip()
    if not token:
        return None
    if "/" in token:
        part, proto = token.rsplit("/", 1)
        port_str = part.strip()
        protocol = "udp" if proto.strip().lower() == "udp" else "tcp"
    else:
        port_str = token
        protocol = "tcp"
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return (port, protocol)
    except ValueError:
        pass
    return None


class ForwardManager:
    """Manages socat port forwarding services (TCP and UDP)."""
    
    def __init__(self, config):
        self.config = config
    
    def _get_service_name(self, port: int, protocol: str) -> str:
        """Get systemd service name for a port and protocol."""
        protocol = protocol.lower() if protocol else "tcp"
        if protocol not in ("tcp", "udp"):
            protocol = "tcp"
        return f"vortexl2-fwd-{port}-{protocol}.service"
    
    def _get_service_path(self, port: int, protocol: str) -> Path:
        """Get path to the service file for a port and protocol."""
        return SYSTEMD_DIR / self._get_service_name(port, protocol)
    
    def _get_template(self, protocol: str) -> str:
        return SERVICE_TEMPLATE_UDP if protocol.lower() == "udp" else SERVICE_TEMPLATE_TCP
    
    def create_forward(self, port: int, protocol: str = "tcp") -> Tuple[bool, str]:
        """Create and start a port forward service (TCP or UDP)."""
        protocol = protocol.lower() if protocol else "tcp"
        if protocol not in ("tcp", "udp"):
            protocol = "tcp"
        remote_ip = self.config.remote_forward_ip
        if not remote_ip:
            return False, "Remote forward IP not configured"
        if not (1 <= port <= 65535):
            return False, f"Port {port} out of range (1-65535)"
        
        # Migrate legacy service (vortexl2-fwd-{port}.service) to new name
        legacy_name = f"vortexl2-fwd-{port}.service"
        legacy_path = SYSTEMD_DIR / legacy_name
        if legacy_path.exists():
            run_command(f"systemctl stop {legacy_name}")
            run_command(f"systemctl disable {legacy_name}")
            legacy_path.unlink()
            run_command("systemctl daemon-reload")
        
        service_path = self._get_service_path(port, protocol)
        service_name = self._get_service_name(port, protocol)
        template = self._get_template(protocol)
        service_content = template.format(port=port, remote_ip=remote_ip)
        
        try:
            with open(service_path, 'w') as f:
                f.write(service_content)
        except Exception as e:
            return False, f"Failed to create service file: {e}"
        
        run_command("systemctl daemon-reload")
        success, output = run_command(f"systemctl enable --now {service_name}")
        if not success:
            return False, f"Failed to start forward for {port}/{protocol}: {output}"
        
        self.config.add_port(port, protocol)
        return True, f"Port forward {port}/{protocol.upper()} created (-> {remote_ip}:{port})"
    
    def remove_forward(self, port: int, protocol: str) -> Tuple[bool, str]:
        """Stop, disable and remove a port forward service."""
        protocol = protocol.lower() if protocol else "tcp"
        if protocol not in ("tcp", "udp"):
            protocol = "tcp"
        service_name = self._get_service_name(port, protocol)
        service_path = self._get_service_path(port, protocol)
        
        run_command(f"systemctl stop {service_name}")
        run_command(f"systemctl disable {service_name}")
        if service_path.exists():
            service_path.unlink()
        run_command("systemctl daemon-reload")
        self.config.remove_port(port, protocol)
        return True, f"Port forward {port}/{protocol.upper()} removed"
    
    def add_multiple_forwards(self, ports_str: str) -> Tuple[bool, str]:
        """Add multiple port forwards. Format: 443, 80, 53/udp (default is tcp)."""
        results = []
        tokens = [t.strip() for t in ports_str.split(",") if t.strip()]
        for token in tokens:
            parsed = _parse_port_protocol(token)
            if parsed is None:
                results.append(f"'{token}': Invalid (use port or port/udp, 1-65535)")
                continue
            port, protocol = parsed
            success, msg = self.create_forward(port, protocol)
            results.append(f"Port {port}/{protocol.upper()}: {msg}")
        return True, "\n".join(results)
    
    def remove_multiple_forwards(self, ports_str: str) -> Tuple[bool, str]:
        """Remove multiple port forwards. Format: 443, 53/udp (default is tcp)."""
        results = []
        tokens = [t.strip() for t in ports_str.split(",") if t.strip()]
        for token in tokens:
            parsed = _parse_port_protocol(token)
            if parsed is None:
                results.append(f"'{token}': Invalid (use port or port/udp, 1-65535)")
                continue
            port, protocol = parsed
            success, msg = self.remove_forward(port, protocol)
            results.append(f"Port {port}/{protocol.upper()}: {msg}")
        return True, "\n".join(results)
    
    def list_forwards(self) -> List[Dict]:
        """List all configured port forwards with status (from config list of dicts)."""
        forwards = []
        for entry in self.config.forwarded_ports:
            port = entry["port"]
            protocol = entry["protocol"]
            service_name = self._get_service_name(port, protocol)
            success, output = run_command(f"systemctl is-active {service_name}")
            status = output if success else "inactive"
            success, output = run_command(f"systemctl is-enabled {service_name}")
            enabled = output if success else "disabled"
            forwards.append({
                "port": port,
                "protocol": protocol.upper(),
                "status": status,
                "enabled": enabled,
                "remote": f"{self.config.remote_forward_ip}:{port}",
            })
        return forwards
    
    def start_all_forwards(self) -> Tuple[bool, str]:
        """Start all configured port forwards."""
        results = []
        for entry in self.config.forwarded_ports:
            port = entry["port"]
            protocol = entry["protocol"]
            service_name = self._get_service_name(port, protocol)
            service_path = self._get_service_path(port, protocol)
            if not service_path.exists():
                success, msg = self.create_forward(port, protocol)
                results.append(f"Port {port}/{protocol.upper()}: recreated and started")
            else:
                success, output = run_command(f"systemctl start {service_name}")
                if success:
                    results.append(f"Port {port}/{protocol.upper()}: started")
                else:
                    results.append(f"Port {port}/{protocol.upper()}: failed - {output}")
        if not results:
            return True, "No port forwards configured"
        return True, "\n".join(results)
    
    def stop_all_forwards(self) -> Tuple[bool, str]:
        """Stop all configured port forwards."""
        results = []
        for entry in self.config.forwarded_ports:
            port = entry["port"]
            protocol = entry["protocol"]
            service_name = self._get_service_name(port, protocol)
            success, output = run_command(f"systemctl stop {service_name}")
            if success:
                results.append(f"Port {port}/{protocol.upper()}: stopped")
            else:
                results.append(f"Port {port}/{protocol.upper()}: failed to stop - {output}")
        if not results:
            return True, "No port forwards configured"
        return True, "\n".join(results)
    
    def restart_all_forwards(self) -> Tuple[bool, str]:
        """Restart all configured port forwards."""
        results = []
        for entry in self.config.forwarded_ports:
            port = entry["port"]
            protocol = entry["protocol"]
            service_name = self._get_service_name(port, protocol)
            service_path = self._get_service_path(port, protocol)
            remote_ip = self.config.remote_forward_ip
            if not service_path.exists():
                success, msg = self.create_forward(port, protocol)
                results.append(f"Port {port}/{protocol.upper()}: recreated")
            else:
                template = self._get_template(protocol)
                service_content = template.format(port=port, remote_ip=remote_ip)
                try:
                    with open(service_path, 'w') as f:
                        f.write(service_content)
                except Exception as e:
                    results.append(f"Port {port}/{protocol.upper()}: failed to write - {e}")
                    continue
                run_command("systemctl daemon-reload")
                success, output = run_command(f"systemctl restart {service_name}")
                if success:
                    results.append(f"Port {port}/{protocol.upper()}: restarted")
                else:
                    results.append(f"Port {port}/{protocol.upper()}: failed - {output}")
        if not results:
            return True, "No port forwards configured"
        return True, "\n".join(results)
