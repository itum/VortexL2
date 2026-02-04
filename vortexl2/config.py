"""
VortexL2 Configuration Management

Handles loading/saving configuration from /etc/vortexl2/config.yaml
with secure file permissions.
"""

import os
import yaml
from pathlib import Path
from typing import Optional, List, Dict, Any


CONFIG_DIR = Path("/etc/vortexl2")
CONFIG_FILE = CONFIG_DIR / "config.yaml"


class Config:
    """Configuration manager for VortexL2."""
    
    # Default values
    DEFAULTS = {
        "version": "1.0.0",
        "tunnel_name": "tunnel1",
        "local_ip": None,
        "remote_ip": None,
        "interface_ip": "10.30.30.1/24",
        "remote_forward_ip": "10.30.30.2",
        "forwarded_ports": [],
        # Tunnel IDs with defaults
        "tunnel_id": 1000,
        "peer_tunnel_id": 2000,
        "session_id": 10,
        "peer_session_id": 20,
    }
    
    def __init__(self):
        self._config: Dict[str, Any] = {}
        self._load()
    
    def _load(self) -> None:
        """Load configuration from file or create defaults."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    self._config = yaml.safe_load(f) or {}
            except Exception:
                self._config = {}
        
        # Apply defaults for missing keys
        for key, default in self.DEFAULTS.items():
            if key not in self._config:
                self._config[key] = default

    
    def _save(self) -> None:
        """Save configuration to file with secure permissions."""
        # Create config directory if not exists
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        # Write config
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(self._config, f, default_flow_style=False)
        
        # Set secure permissions (owner read/write only)
        os.chmod(CONFIG_FILE, 0o600)
    
    def save(self) -> None:
        """Public method to save configuration."""
        self._save()
    
    @property
    def tunnel_name(self) -> str:
        return self._config.get("tunnel_name", "tunnel1")
    
    @tunnel_name.setter
    def tunnel_name(self, value: str) -> None:
        self._config["tunnel_name"] = value
        self._save()
    
    @property
    def local_ip(self) -> Optional[str]:
        return self._config.get("local_ip")
    
    @local_ip.setter
    def local_ip(self, value: str) -> None:
        self._config["local_ip"] = value
        self._save()
    
    @property
    def remote_ip(self) -> Optional[str]:
        return self._config.get("remote_ip")
    
    @remote_ip.setter
    def remote_ip(self, value: str) -> None:
        self._config["remote_ip"] = value
        self._save()
    
    @property
    def interface_ip(self) -> str:
        return self._config.get("interface_ip", "10.30.30.1/24")
    
    @interface_ip.setter
    def interface_ip(self, value: str) -> None:
        self._config["interface_ip"] = value
        self._save()
    
    @property
    def remote_forward_ip(self) -> str:
        return self._config.get("remote_forward_ip", "10.30.30.2")
    
    @remote_forward_ip.setter
    def remote_forward_ip(self, value: str) -> None:
        self._config["remote_forward_ip"] = value
        self._save()
    
    @property
    def forwarded_ports(self) -> List[int]:
        return self._config.get("forwarded_ports", [])
    
    @forwarded_ports.setter
    def forwarded_ports(self, value: List[int]) -> None:
        self._config["forwarded_ports"] = value
        self._save()
    
    @property
    def tunnel_id(self) -> int:
        return self._config.get("tunnel_id", 1000)
    
    @tunnel_id.setter
    def tunnel_id(self, value: int) -> None:
        self._config["tunnel_id"] = value
        self._save()
    
    @property
    def peer_tunnel_id(self) -> int:
        return self._config.get("peer_tunnel_id", 2000)
    
    @peer_tunnel_id.setter
    def peer_tunnel_id(self, value: int) -> None:
        self._config["peer_tunnel_id"] = value
        self._save()
    
    @property
    def session_id(self) -> int:
        return self._config.get("session_id", 10)
    
    @session_id.setter
    def session_id(self, value: int) -> None:
        self._config["session_id"] = value
        self._save()
    
    @property
    def peer_session_id(self) -> int:
        return self._config.get("peer_session_id", 20)
    
    @peer_session_id.setter
    def peer_session_id(self, value: int) -> None:
        self._config["peer_session_id"] = value
        self._save()
    
    def get_tunnel_ids(self) -> Dict[str, int]:
        """Get all tunnel IDs as a dictionary."""
        return {
            "tunnel_id": self.tunnel_id,
            "peer_tunnel_id": self.peer_tunnel_id,
            "session_id": self.session_id,
            "peer_session_id": self.peer_session_id,
        }
    
    def add_port(self, port: int) -> None:
        """Add a port to forwarded ports list."""
        ports = self.forwarded_ports
        if port not in ports:
            ports.append(port)
            self.forwarded_ports = ports
    
    def remove_port(self, port: int) -> None:
        """Remove a port from forwarded ports list."""
        ports = self.forwarded_ports
        if port in ports:
            ports.remove(port)
            self.forwarded_ports = ports
    
    def clear_all(self) -> None:
        """Clear all configuration values (used when deleting tunnel)."""
        self._config["local_ip"] = None
        self._config["remote_ip"] = None
        self._config["forwarded_ports"] = []
        self._save()
    
    def is_configured(self) -> bool:
        """Check if basic configuration is complete."""
        return bool(
            self.local_ip and 
            self.remote_ip
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary."""
        return self._config.copy()
