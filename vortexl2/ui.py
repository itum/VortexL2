"""
VortexL2 Terminal User Interface

Rich-based TUI with ASCII banner and menu system.
"""

import os
import sys
from typing import Optional, Callable

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich import box
except ImportError:
    print("Error: 'rich' library is required. Install with: pip install rich")
    sys.exit(1)

from . import __version__
from .config import Config


console = Console()


ASCII_BANNER = r"""
 __      __        _            _     ___  
 \ \    / /       | |          | |   |__ \ 
  \ \  / /__  _ __| |_ _____  _| |      ) |
   \ \/ / _ \| '__| __/ _ \ \/ / |     / / 
    \  / (_) | |  | ||  __/>  <| |____/ /_ 
     \/ \___/|_|   \__\___/_/\_\______|____|
"""


def clear_screen():
    """Clear terminal screen."""
    os.system('clear' if os.name != 'nt' else 'cls')


def show_banner(config: Config):
    """Display the ASCII banner with system info."""
    clear_screen()
    
    banner_text = Text(ASCII_BANNER, style="bold cyan")
    
    # Print banner
    console.print(banner_text)
    
    # Contact info bar
    console.print(Panel(
        f"[bold white]Telegram:[/] [cyan]@iliyadevsh[/]  |  [bold white]Version:[/] [red]{__version__}[/]  |  [bold white]GitHub:[/] [cyan]github.com/iliya-Developer[/]",
        border_style="white",
        box=box.ROUNDED
    ))
    
    # Server info
    tunnel_name = config.tunnel_name or "Not set"
    local_ip = config.local_ip or "Not configured"
    remote_ip = config.remote_ip or "Not configured"
    
    info_lines = [
        f"[bold white]Tunnel Name:[/] [magenta]{tunnel_name}[/]",
        f"[bold white]Local IP:[/] [green]{local_ip}[/]",
        f"[bold white]Remote IP:[/] [cyan]{remote_ip}[/]",
    ]
    
    console.print(Panel(
        "\n".join(info_lines),
        title="[bold white]VortexL2 - L2TPv3 Tunnel Manager[/]",
        border_style="cyan",
        box=box.ROUNDED
    ))
    console.print()


def show_main_menu() -> str:
    """Display main menu and get user choice."""
    menu_items = [
        ("1", "Install/Verify Prerequisites"),
        ("2", "Configure Tunnel"),
        ("3", "Create/Start Tunnel"),
        ("4", "Stop/Delete Tunnel"),
        ("5", "Port Forwards"),
        ("6", "Status/Diagnostics"),
        ("7", "View Logs"),
        ("0", "Exit"),
    ]
    
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Option", style="bold cyan", width=4)
    table.add_column("Description", style="white")
    
    for opt, desc in menu_items:
        table.add_row(f"[{opt}]", desc)
    
    console.print(Panel(table, title="[bold white]Main Menu[/]", border_style="blue"))
    
    return Prompt.ask("\n[bold cyan]Select option[/]", default="0")


def show_forwards_menu() -> str:
    """Display forwards submenu."""
    menu_items = [
        ("1", "Add Port Forwards"),
        ("2", "Remove Port Forwards"),
        ("3", "List Port Forwards"),
        ("4", "Restart All Forwards"),
        ("5", "Stop All Forwards"),
        ("6", "Start All Forwards"),
        ("0", "Back to Main Menu"),
    ]
    
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Option", style="bold cyan", width=4)
    table.add_column("Description", style="white")
    
    for opt, desc in menu_items:
        table.add_row(f"[{opt}]", desc)
    
    console.print(Panel(table, title="[bold white]Port Forwards[/]", border_style="green"))
    
    return Prompt.ask("\n[bold cyan]Select option[/]", default="0")


def prompt_endpoints(config: Config) -> bool:
    """Prompt user for tunnel configuration."""
    console.print("\n[bold white]Configure Tunnel[/]")
    console.print("[dim]Enter tunnel configuration values. Press Enter to use defaults.[/]\n")
    
    # Tunnel Name
    tunnel_name = Prompt.ask(
        "[bold magenta]Tunnel Name[/]",
        default=config.tunnel_name
    )
    config.tunnel_name = tunnel_name
    
    # Local IP
    default_local = config.local_ip or ""
    local_ip = Prompt.ask(
        "[bold green]Local Server Public IP[/]",
        default=default_local if default_local else None
    )
    if not local_ip:
        console.print("[red]Local IP is required[/]")
        return False
    config.local_ip = local_ip
    
    # Remote IP
    default_remote = config.remote_ip or ""
    remote_ip = Prompt.ask(
        "[bold cyan]Remote Server Public IP[/]",
        default=default_remote if default_remote else None
    )
    if not remote_ip:
        console.print("[red]Remote IP is required[/]")
        return False
    config.remote_ip = remote_ip
    
    # Interface IP
    console.print("\n[dim]Configure tunnel interface IP (for l2tpeth0)[/]")
    interface_ip = Prompt.ask(
        "[bold yellow]Interface IP (CIDR)[/]",
        default=config.interface_ip
    )
    config.interface_ip = interface_ip
    
    # Remote forward target IP
    remote_forward = Prompt.ask(
        "[bold yellow]Remote Forward Target IP[/]",
        default=config.remote_forward_ip
    )
    config.remote_forward_ip = remote_forward
    
    # Tunnel IDs
    console.print("\n[dim]Configure L2TPv3 tunnel IDs (press Enter to use defaults)[/]")
    
    # Tunnel ID
    tunnel_id_input = Prompt.ask(
        "[bold yellow]Tunnel ID[/]",
        default=str(config.tunnel_id)
    )
    config.tunnel_id = int(tunnel_id_input)
    
    # Peer Tunnel ID
    peer_tunnel_id_input = Prompt.ask(
        "[bold yellow]Peer Tunnel ID[/]",
        default=str(config.peer_tunnel_id)
    )
    config.peer_tunnel_id = int(peer_tunnel_id_input)
    
    # Session ID
    session_id_input = Prompt.ask(
        "[bold yellow]Session ID[/]",
        default=str(config.session_id)
    )
    config.session_id = int(session_id_input)
    
    # Peer Session ID
    peer_session_id_input = Prompt.ask(
        "[bold yellow]Peer Session ID[/]",
        default=str(config.peer_session_id)
    )
    config.peer_session_id = int(peer_session_id_input)
    
    console.print("\n[green]✓ Configuration saved![/]")
    return True


def prompt_ports() -> str:
    """Prompt user for ports to forward."""
    console.print("\n[dim]Enter ports as comma-separated list (e.g., 443,80,2053)[/]")
    return Prompt.ask("[bold cyan]Ports[/]")


def show_success(message: str):
    """Display success message."""
    console.print(f"\n[bold green]✓[/] {message}")


def show_error(message: str):
    """Display error message."""
    console.print(f"\n[bold red]✗[/] {message}")


def show_warning(message: str):
    """Display warning message."""
    console.print(f"\n[bold yellow]![/] {message}")


def show_info(message: str):
    """Display info message."""
    console.print(f"\n[bold cyan]ℹ[/] {message}")


def show_status(status_data: dict):
    """Display tunnel status in a formatted table."""
    table = Table(title="Tunnel Status", box=box.ROUNDED)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Tunnel Name", status_data.get("tunnel_name", "Not set") or "Not set")
    table.add_row("Configured", "Yes" if status_data.get("configured") else "No")
    table.add_row("Local IP", status_data.get("local_ip") or "Not set")
    table.add_row("Remote IP", status_data.get("remote_ip") or "Not set")
    table.add_row("Tunnel Exists", "[green]Yes[/]" if status_data.get("tunnel_exists") else "[red]No[/]")
    table.add_row("Session Exists", "[green]Yes[/]" if status_data.get("session_exists") else "[red]No[/]")
    table.add_row("Interface Up", "[green]Yes[/]" if status_data.get("interface_up") else "[red]No[/]")
    table.add_row("Interface IP", status_data.get("interface_ip") or "None")
    
    console.print(table)
    
    if status_data.get("tunnel_info"):
        console.print(Panel(status_data["tunnel_info"], title="Tunnel Info", border_style="dim"))
    
    if status_data.get("session_info"):
        console.print(Panel(status_data["session_info"], title="Session Info", border_style="dim"))


def show_forwards_list(forwards: list):
    """Display port forwards in a table."""
    if not forwards:
        console.print("[yellow]No port forwards configured[/]")
        return
    
    table = Table(title="Port Forwards", box=box.ROUNDED)
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Remote Target", style="white")
    table.add_column("Status", style="white")
    table.add_column("Enabled", style="white")
    
    for fwd in forwards:
        status_style = "green" if fwd["status"] == "active" else "red"
        enabled_style = "green" if fwd["enabled"] == "enabled" else "yellow"
        
        table.add_row(
            str(fwd["port"]),
            fwd["remote"],
            f"[{status_style}]{fwd['status']}[/]",
            f"[{enabled_style}]{fwd['enabled']}[/]"
        )
    
    console.print(table)


def show_output(output: str, title: str = "Output"):
    """Display command output in a panel."""
    console.print(Panel(output, title=title, border_style="dim"))


def wait_for_enter():
    """Wait for user to press Enter."""
    console.print()
    Prompt.ask("[dim]Press Enter to continue[/]", default="")


def confirm(message: str, default: bool = False) -> bool:
    """Ask for confirmation."""
    return Confirm.ask(message, default=default)
