#!/usr/bin/env python3
"""
WiFi Scanner TUI - Advanced Cybersecurity Tool
Uses Python + Rich for a beautiful terminal UI
Requires: pip install rich scapy
Run as root: sudo python3 wifi_scanner_tui.py
"""

import subprocess
import re
import time
import sys
import os
import platform
from datetime import datetime
from threading import Thread, Event

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.style import Style
from rich.rule import Rule
from rich.prompt import Prompt, Confirm
from rich.traceback import install

install()  # Pretty tracebacks

console = Console()

# ─── Data Store ────────────────────────────────────────────────────────────────

networks = {}          # { bssid: { ...fields } }
scan_count = 0
start_time = datetime.now()
stop_event = Event()

# ─── Security Rating ───────────────────────────────────────────────────────────

def security_score(encryption: str, auth: str) -> tuple[str, str]:
    enc = encryption.upper()
    if "WPA3" in enc:
        return "[bold green]WPA3[/bold green]", "green"
    elif "WPA2" in enc:
        return "[green]WPA2[/green]", "green"
    elif "WPA" in enc:
        return "[yellow]WPA[/yellow]", "yellow"
    elif "WEP" in enc:
        return "[bold red]WEP ⚠[/bold red]", "red"
    elif "OPEN" in enc or enc == "":
        return "[bold red]OPEN ⚠[/bold red]", "red"
    else:
        return f"[dim]{encryption}[/dim]", "dim"

def signal_bar(signal_dbm: int) -> str:
    try:
        dbm = int(signal_dbm)
    except (ValueError, TypeError):
        return "[dim]—[/dim]"
    if dbm >= -50:
        return "[bold green]████[/bold green]  Excellent"
    elif dbm >= -60:
        return "[green]███[/green]░  Good"
    elif dbm >= -70:
        return "[yellow]██[/yellow]░░  Fair"
    elif dbm >= -80:
        return "[red]█[/red]░░░  Weak"
    else:
        return "[dim]░░░░  Very Weak[/dim]"

def channel_band(channel: str) -> str:
    try:
        ch = int(channel)
        if ch <= 14:
            return "[cyan]2.4 GHz[/cyan]"
        else:
            return "[magenta]5 GHz[/magenta]"
    except (ValueError, TypeError):
        return "[dim]—[/dim]"

# ─── Scanner Backends ──────────────────────────────────────────────────────────

def scan_linux() -> dict:
    """Use iwlist or nmcli on Linux."""
    found = {}
    try:
        # Try nmcli first (more reliable)
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY",
             "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=15
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split(":")
            if len(parts) < 8:
                continue
            ssid, bssid, mode, chan, freq, rate, signal, security = parts[:8]
            bssid = bssid.replace("\\", "")
            if not bssid:
                continue
            found[bssid] = {
                "ssid": ssid or "<Hidden>",
                "bssid": bssid,
                "channel": chan,
                "frequency": freq,
                "signal": signal,
                "rate": rate,
                "security": security or "OPEN",
                "mode": mode,
                "first_seen": found.get(bssid, {}).get("first_seen", datetime.now().strftime("%H:%M:%S")),
                "last_seen": datetime.now().strftime("%H:%M:%S"),
            }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Fallback: iwlist
        try:
            iface = get_wireless_interface()
            result = subprocess.run(
                ["iwlist", iface, "scan"],
                capture_output=True, text=True, timeout=15
            )
            _parse_iwlist(result.stdout, found)
        except Exception:
            pass
    return found


def scan_macos() -> dict:
    """Use airport on macOS."""
    found = {}
    airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    try:
        result = subprocess.run(
            [airport, "-s"],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.strip().splitlines()
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) < 7:
                continue
            ssid = parts[0]
            bssid = parts[1]
            signal = parts[2]
            channel = parts[3]
            security = " ".join(parts[6:]) if len(parts) > 6 else "OPEN"
            found[bssid] = {
                "ssid": ssid or "<Hidden>",
                "bssid": bssid,
                "channel": channel,
                "frequency": "",
                "signal": signal,
                "rate": "—",
                "security": security,
                "mode": "Infra",
                "first_seen": found.get(bssid, {}).get("first_seen", datetime.now().strftime("%H:%M:%S")),
                "last_seen": datetime.now().strftime("%H:%M:%S"),
            }
    except Exception:
        pass
    return found


def scan_windows() -> dict:
    """Use netsh on Windows."""
    found = {}
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=15
        )
        blocks = result.stdout.split("SSID")[1:]
        for i, block in enumerate(blocks):
            lines = block.strip().splitlines()
            data = {}
            for line in lines:
                if ":" in line:
                    k, _, v = line.partition(":")
                    data[k.strip().lower()] = v.strip()
            ssid = lines[0].split(":", 1)[-1].strip() if lines else f"Network_{i}"
            bssid = data.get("bssid 1", f"00:00:00:00:00:{i:02x}")
            found[bssid] = {
                "ssid": ssid or "<Hidden>",
                "bssid": bssid,
                "channel": data.get("channel", "—"),
                "frequency": "",
                "signal": data.get("signal", "—").replace("%", ""),
                "rate": data.get("radio type", "—"),
                "security": data.get("authentication", "OPEN"),
                "mode": "Infra",
                "first_seen": found.get(bssid, {}).get("first_seen", datetime.now().strftime("%H:%M:%S")),
                "last_seen": datetime.now().strftime("%H:%M:%S"),
            }
    except Exception:
        pass
    return found


def _parse_iwlist(output: str, found: dict):
    cells = output.split("Cell ")
    for cell in cells[1:]:
        bssid = re.search(r"Address: ([0-9A-Fa-f:]{17})", cell)
        ssid = re.search(r'ESSID:"([^"]*)"', cell)
        channel = re.search(r"Channel[=:](\d+)", cell)
        signal = re.search(r"Signal level=(-?\d+)", cell)
        security = "OPEN"
        if "WPA2" in cell:
            security = "WPA2"
        elif "WPA" in cell:
            security = "WPA"
        elif "WEP" in cell:
            security = "WEP"
        if bssid:
            b = bssid.group(1)
            found[b] = {
                "ssid": ssid.group(1) if ssid else "<Hidden>",
                "bssid": b,
                "channel": channel.group(1) if channel else "—",
                "frequency": "",
                "signal": signal.group(1) if signal else "—",
                "rate": "—",
                "security": security,
                "mode": "Infra",
                "first_seen": found.get(b, {}).get("first_seen", datetime.now().strftime("%H:%M:%S")),
                "last_seen": datetime.now().strftime("%H:%M:%S"),
            }


def get_wireless_interface() -> str:
    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "IEEE" in line:
                return line.split()[0]
    except Exception:
        pass
    return "wlan0"


def do_scan() -> dict:
    system = platform.system()
    if system == "Linux":
        return scan_linux()
    elif system == "Darwin":
        return scan_macos()
    elif system == "Windows":
        return scan_windows()
    return {}

# ─── UI Builders ───────────────────────────────────────────────────────────────

def build_header() -> Panel:
    elapsed = str(datetime.now() - start_time).split(".")[0]
    title = Text("  WiFi Scanner TUI  ", style="bold white on dark_blue")
    sub = Text(
        f"  Scans: {scan_count}   |   Networks: {len(networks)}   |   Uptime: {elapsed}   |   {datetime.now().strftime('%H:%M:%S')}  ",
        style="dim"
    )
    return Panel(
        Align.center(Text.assemble(title, "\n", sub)),
        style="bold blue",
        box=box.DOUBLE_EDGE,
    )


def build_table(sort_by: str = "signal", filter_text: str = "") -> Table:
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        expand=True,
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("SSID", min_width=16, max_width=28)
    table.add_column("BSSID", style="dim cyan", width=19)
    table.add_column("Security", width=14)
    table.add_column("Signal", min_width=20)
    table.add_column("Ch", justify="center", width=4)
    table.add_column("Band", justify="center", width=10)
    table.add_column("Rate", justify="right", width=10)
    table.add_column("First seen", width=10)
    table.add_column("Last seen", width=10)

    data = list(networks.values())

    # Filter
    if filter_text:
        ft = filter_text.lower()
        data = [n for n in data if ft in n["ssid"].lower() or ft in n["bssid"].lower()]

    # Sort
    if sort_by == "signal":
        data.sort(key=lambda x: int(x["signal"]) if str(x["signal"]).lstrip("-").isdigit() else -999, reverse=True)
    elif sort_by == "ssid":
        data.sort(key=lambda x: x["ssid"].lower())
    elif sort_by == "channel":
        data.sort(key=lambda x: int(x["channel"]) if str(x["channel"]).isdigit() else 0)
    elif sort_by == "security":
        order = {"WPA3": 0, "WPA2": 1, "WPA": 2, "WEP": 3, "OPEN": 4}
        data.sort(key=lambda x: order.get(x["security"].upper().split()[0], 5))

    for i, net in enumerate(data, 1):
        sec_label, _ = security_score(net["security"], "")
        row_style = ""
        if "OPEN" in net["security"].upper() or "WEP" in net["security"].upper():
            row_style = "on dark_red" if "OPEN" in net["security"].upper() else ""

        table.add_row(
            str(i),
            f"[bold]{net['ssid']}[/bold]",
            net["bssid"],
            sec_label,
            signal_bar(net["signal"]),
            net["channel"],
            channel_band(net["channel"]),
            net.get("rate", "—"),
            net["first_seen"],
            net["last_seen"],
            style=row_style,
        )

    return table


def build_stats() -> Columns:
    total = len(networks)
    open_nets = sum(1 for n in networks.values() if "OPEN" in n["security"].upper())
    wpa3 = sum(1 for n in networks.values() if "WPA3" in n["security"].upper())
    wpa2 = sum(1 for n in networks.values() if "WPA2" in n["security"].upper())
    wep = sum(1 for n in networks.values() if "WEP" in n["security"].upper())
    ch24 = sum(1 for n in networks.values() if str(n["channel"]).isdigit() and int(n["channel"]) <= 14)
    ch5 = sum(1 for n in networks.values() if str(n["channel"]).isdigit() and int(n["channel"]) > 14)

    def stat_panel(label, value, color="white"):
        return Panel(
            Align.center(Text(str(value), style=f"bold {color} on default", justify="center")),
            title=f"[dim]{label}[/dim]",
            border_style=color,
            padding=(0, 2),
        )

    return Columns([
        stat_panel("Total", total, "cyan"),
        stat_panel("WPA3", wpa3, "green"),
        stat_panel("WPA2", wpa2, "green"),
        stat_panel("WEP ⚠", wep, "red"),
        stat_panel("Open ⚠", open_nets, "bright_red"),
        stat_panel("2.4 GHz", ch24, "yellow"),
        stat_panel("5 GHz", ch5, "magenta"),
    ], equal=True, expand=True)


def build_footer(sort_by: str, filter_text: str) -> Panel:
    keys = Text()
    keys.append(" [S] ", style="bold yellow")
    keys.append("Sort  ", style="dim")
    keys.append(" [F] ", style="bold yellow")
    keys.append("Filter  ", style="dim")
    keys.append(" [E] ", style="bold yellow")
    keys.append("Export  ", style="dim")
    keys.append(" [R] ", style="bold yellow")
    keys.append("Rescan  ", style="dim")
    keys.append(" [Q] ", style="bold yellow")
    keys.append("Quit  ", style="dim")
    info = f"  Sort: [bold cyan]{sort_by}[/bold cyan]   Filter: [bold cyan]{filter_text or 'none'}[/bold cyan]  "
    return Panel(
        Align.center(Text.assemble(keys, "\n", Text(info, style="dim"))),
        style="dim",
        box=box.SIMPLE,
    )

# ─── Export ────────────────────────────────────────────────────────────────────

def export_csv():
    filename = f"wifi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w") as f:
        f.write("SSID,BSSID,Security,Signal,Channel,Rate,FirstSeen,LastSeen\n")
        for n in networks.values():
            f.write(f"{n['ssid']},{n['bssid']},{n['security']},{n['signal']},{n['channel']},{n.get('rate','')},{n['first_seen']},{n['last_seen']}\n")
    return filename

# ─── Background Scanner ────────────────────────────────────────────────────────

def background_scanner(interval: int = 5):
    global networks, scan_count
    while not stop_event.is_set():
        new = do_scan()
        for bssid, data in new.items():
            if bssid in networks:
                data["first_seen"] = networks[bssid]["first_seen"]
            networks[bssid] = data
        scan_count += 1
        stop_event.wait(interval)

# ─── Interactive Menu ──────────────────────────────────────────────────────────

def run_interactive(sort_by="signal", filter_text="", scan_interval=5):
    global stop_event, networks

    # Start background scanner
    scanner_thread = Thread(target=background_scanner, args=(scan_interval,), daemon=True)
    scanner_thread.start()

    sort_options = ["signal", "ssid", "channel", "security"]
    sort_idx = 0

    def make_renderable():
        from rich.console import Group
        return Group(
            build_header(),
            build_stats(),
            Rule(style="dim blue"),
            build_table(sort_by, filter_text),
            build_footer(sort_by, filter_text),
        )

    console.clear()
    with Live(make_renderable(), refresh_per_second=2, screen=True) as live:
        while True:
            live.update(make_renderable())
            try:
                import select
                if platform.system() != "Windows":
                    import tty, termios
                    fd = sys.stdin.fileno()
                    old = termios.tcgetattr(fd)
                    try:
                        tty.setraw(fd)
                        rlist, _, _ = select.select([sys.stdin], [], [], 0.5)
                        if rlist:
                            key = sys.stdin.read(1).lower()
                        else:
                            continue
                    finally:
                        termios.tcsetattr(fd, termios.TCSADRAIN, old)
                else:
                    import msvcrt
                    if msvcrt.kbhit():
                        key = msvcrt.getch().decode("utf-8", errors="ignore").lower()
                    else:
                        time.sleep(0.5)
                        continue
            except Exception:
                time.sleep(0.5)
                continue

            if key == "q":
                stop_event.set()
                break
            elif key == "s":
                sort_idx = (sort_idx + 1) % len(sort_options)
                sort_by = sort_options[sort_idx]
            elif key == "r":
                networks = {}
                scan_count = 0
            elif key == "f":
                stop_event.set()
                scanner_thread.join(timeout=2)
                console.clear()
                filter_text = Prompt.ask("[cyan]Filter by SSID or BSSID[/cyan] (blank to clear)")
                stop_event.clear()
                scanner_thread = Thread(target=background_scanner, args=(scan_interval,), daemon=True)
                scanner_thread.start()
            elif key == "e":
                fname = export_csv()
                console.print(f"\n[green]Exported to [bold]{fname}[/bold][/green]")
                time.sleep(1.5)

    console.clear()
    console.print(Panel("[bold green]Scan complete. Goodbye![/bold green]", box=box.DOUBLE))

# ─── Startup ───────────────────────────────────────────────────────────────────

def check_dependencies():
    missing = []
    try:
        import rich
    except ImportError:
        missing.append("rich")
    if missing:
        console.print(f"[red]Missing packages: {', '.join(missing)}[/red]")
        console.print(f"[yellow]Install with: pip install {' '.join(missing)}[/yellow]")
        sys.exit(1)


def show_splash():
    splash = """
 ██╗    ██╗██╗███████╗██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║    ██║██║██╔════╝██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║ █╗ ██║██║█████╗  ██║    ███████╗██║     ███████║██╔██╗ ██║
 ██║███╗██║██║██╔══╝  ██║    ╚════██║██║     ██╔══██║██║╚██╗██║
 ╚███╔███╔╝██║██║     ██║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """
    console.print(Panel(
        Align.center(Text(splash, style="bold cyan")),
        subtitle="[dim]Python + Rich  |  Educational Use Only[/dim]",
        border_style="blue",
        box=box.DOUBLE_EDGE,
    ))


def main():
    check_dependencies()
    console.clear()
    show_splash()
    time.sleep(1.2)

    if platform.system() == "Linux" and os.geteuid() != 0:
        console.print("[yellow]Warning: Run as root (sudo) for full scanning capability.[/yellow]")
        time.sleep(1)

    interval = Prompt.ask("[cyan]Scan interval (seconds)[/cyan]", default="5")
    try:
        interval = max(2, int(interval))
    except ValueError:
        interval = 5

    console.print("[dim]Starting scanner...[/dim]")
    time.sleep(0.5)

    run_interactive(scan_interval=interval)


if __name__ == "__main__":
    main()
