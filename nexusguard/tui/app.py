"""
Beautiful TUI Application using Textual
"""

from textual.app import App, ComposeResult
from textual.widgets import (
    Header, Footer, Static, DataTable, TabbedContent, 
    TabPane, Button, Input, Label, ProgressBar, Switch
)
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.reactive import reactive
from rich.text import Text
from rich.panel import Panel
from rich.table import Table as RichTable
from rich.console import Group
from rich.progress import Progress, SpinnerColumn, TextColumn
from datetime import datetime
import asyncio

from ..core.packet_capture import PacketCapture
from ..core.threat_detector import ThreatDetector
from ..core.firewall_manager import FirewallManager


BANNER = """
[bold cyan]╔═══════════════════════════════════════════════════════════════╗[/]
[bold cyan]║[/] [bold magenta on black]  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗  [/] [bold cyan]║[/]
[bold cyan]║[/] [bold magenta on black]  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝  [/] [bold cyan]║[/]
[bold cyan]║[/] [bold blue on black]  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗  [/] [bold cyan]║[/]
[bold cyan]║[/] [bold blue on black]  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║  [/] [bold cyan]║[/]
[bold cyan]║[/] [bold green on black]  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║  [/] [bold cyan]║[/]
[bold cyan]║[/] [bold green on black]  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝  [/] [bold cyan]║[/]
[bold cyan]║[/]                                                             [bold cyan]║[/]
[bold cyan]║[/]      [bold white]🛡️  Advanced Intrusion Prevention System[/]          [bold cyan]║[/]
[bold cyan]║[/]          [dim]Real-time • Intelligent • Beautiful[/]              [bold cyan]║[/]
[bold cyan]╚═══════════════════════════════════════════════════════════════╝[/]
"""


class StatsPanel(Static):
    """Live statistics panel"""
    
    packets_total = reactive(0)
    threats_detected = reactive(0)
    ips_blocked = reactive(0)
    
    def render(self):
        table = RichTable.grid(padding=(0, 2))
        table.add_column(style="bold cyan")
        table.add_column(style="bold yellow")
        
        table.add_row("📦 Total Packets:", f"{self.packets_total:,}")
        table.add_row("⚠️  Threats Detected:", f"[red]{self.threats_detected}[/]")
        table.add_row("🚫 IPs Blocked:", f"[red]{self.ips_blocked}[/]")
        table.add_row("⏱️  Uptime:", self._get_uptime())
        
        return Panel(table, title="[bold]Live Statistics[/]", border_style="cyan")
        
    def _get_uptime(self):
        # Calculate uptime
        return "00:05:23"


class ThreatTable(Static):
    """Display recent threats"""
    
    def __init__(self):
        super().__init__()
        self.threats = []
        
    def render(self):
        table = RichTable(title="Recent Threats", border_style="red")
        table.add_column("Time", style="dim")
        table.add_column("Type", style="bold red")
        table.add_column("Severity")
        table.add_column("Source IP", style="yellow")
        table.add_column("Description")
        
        for threat in self.threats[-10:]:
            severity_color = {
                'CRITICAL': 'bold red',
                'HIGH': 'red',
                'MEDIUM': 'yellow',
                'LOW': 'blue'
            }.get(threat.get('severity', 'LOW'), 'white')
            
            table.add_row(
                threat['timestamp'].strftime("%H:%M:%S"),
                threat['type'],
                f"[{severity_color}]{threat['severity']}[/]",
                threat.get('src_ip', 'N/A'),
                threat['description'][:40]
            )
            
        return table
        
    def add_threat(self, threat):
        self.threats.append(threat)
        self.refresh()


class NexusGuardTUI(App):
    """NexusGuard TUI Application"""
    
    CSS = """
    Screen {
        background: $surface;
    }
    
    #banner {
        height: 11;
        content-align: center middle;
        background: $primary-background;
    }
    
    #main-container {
        height: 1fr;
    }
    
    #stats-panel {
        width: 30;
        height: 100%;
        border: solid cyan;
    }
    
    #content-area {
        width: 1fr;
        height: 100%;
    }
    
    DataTable {
        height: 100%;
    }
    
    .threat-row-critical {
        background: darkred;
    }
    
    .threat-row-high {
        background: red 20%;
    }
    
    Button {
        margin: 1;
    }
    
    #control-panel {
        height: auto;
        background: $panel;
        padding: 1;
    }
    """
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("p", "toggle_protection", "Toggle Protection"),
        ("c", "clear_threats", "Clear Threats"),
        ("b", "block_selected", "Block IP"),
        ("r", "refresh", "Refresh"),
    ]
    
    def __init__(self):
        super().__init__()
        self.capture = None
        self.detector = ThreatDetector()
        self.firewall = FirewallManager()
        self.protection_enabled = False
        
    def compose(self) -> ComposeResult:
        """Create UI layout"""
        yield Header(show_clock=True)
        
        # Banner
        yield Static(BANNER, id="banner")
        
        # Main container
        with Container(id="main-container"):
            with Horizontal():
                # Left sidebar - Stats
                with Vertical(id="stats-panel"):
                    yield StatsPanel()
                    yield Static(id="protection-status")
                    
                    with Vertical(id="control-panel"):
                        yield Label("Quick Actions")
                        yield Button("🛡️ Enable Protection", id="btn-protect", variant="success")
                        yield Button("🚫 Block IP", id="btn-block", variant="error")
                        yield Button("🔄 Refresh Stats", id="btn-refresh")
                        yield Button("🧹 Clear Threats", id="btn-clear")
                
                # Right content area with tabs
                with TabbedContent(id="content-area"):
                    with TabPane("📊 Dashboard", id="tab-dashboard"):
                        yield DataTable(id="packet-table")
                        
                    with TabPane("⚠️ Threats", id="tab-threats"):
                        yield ThreatTable()
                        
                    with TabPane("🚫 Blocked IPs", id="tab-blocked"):
                        yield DataTable(id="blocked-table")
                        
                    with TabPane("⚙️ Settings", id="tab-settings"):
                        yield Static("Settings panel - Coming soon!")
        
        yield Footer()
        
    def on_mount(self) -> None:
        """Initialize tables when app loads"""
        # Setup packet table
        packet_table = self.query_one("#packet-table", DataTable)
        packet_table.add_columns("Time", "Protocol", "Source", "Destination", "Size", "Status")
        
        # Setup blocked IPs table
        blocked_table = self.query_one("#blocked-table", DataTable)
        blocked_table.add_columns("IP Address", "Blocked At", "Reason", "Severity", "Actions")
        
        # Start update loop
        self.set_interval(1, self.update_stats)
        
    def update_stats(self):
        """Update statistics display"""
        stats_panel = self.query_one(StatsPanel)
        
        if self.capture:
            stats = self.capture.get_stats()
            stats_panel.packets_total = stats['total_packets']
            
        detector_stats = self.detector.get_stats()
        stats_panel.threats_detected = detector_stats['threats_detected']
        
        firewall_stats = self.firewall.get_stats()
        stats_panel.ips_blocked = firewall_stats['currently_blocked']
        
    def action_toggle_protection(self):
        """Toggle protection on/off"""
        if not self.protection_enabled:
            self.start_protection()
        else:
            self.stop_protection()
            
    def start_protection(self):
        """Start packet capture and protection"""
        try:
            self.capture = PacketCapture(
                interface="eth0",  # TODO: Make configurable
                callback=self.on_packet
            )
            self.capture.start()
            self.protection_enabled = True
            
            # Update button
            btn = self.query_one("#btn-protect", Button)
            btn.label = "🛡️ Protection ACTIVE"
            btn.variant = "error"
            
            self.notify("Protection enabled!", severity="information")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")
            
    def stop_protection(self):
        """Stop protection"""
        if self.capture:
            self.capture.stop()
            self.protection_enabled = False
            
            btn = self.query_one("#btn-protect", Button)
            btn.label = "🛡️ Enable Protection"
            btn.variant = "success"
            
            self.notify("Protection disabled", severity="warning")
            
    def on_packet(self, packet_data):
        """Handle captured packet"""
        # Analyze for threats
        threats = self.detector.analyze_packet(packet_data)
        
        if threats:
            threat_table = self.query_one(ThreatTable)
            for threat in threats:
                threat_table.add_threat(threat)
                
                # Auto-block critical threats
                if threat['severity'] == 'CRITICAL' and threat.get('src_ip'):
                    self.firewall.block_ip(
                        threat['src_ip'],
                        reason=threat['description'],
                        severity=threat['severity']
                    )
        
        # Update packet table
        self.add_packet_to_table(packet_data)
        
    def add_packet_to_table(self, packet_data):
        """Add packet to display table"""
        packet_table = self.query_one("#packet-table", DataTable)
        
        status = "⚠️ SUSPICIOUS" if packet_data.get('suspicious') else "✅ Normal"
        
        packet_table.add_row(
            packet_data['timestamp'].strftime("%H:%M:%S"),
            packet_data.get('protocol', 'N/A'),
            f"{packet_data.get('src_ip', 'N/A')}:{packet_data.get('src_port', '')}",
            f"{packet_data.get('dst_ip', 'N/A')}:{packet_data.get('dst_port', '')}",
            str(packet_data['size']),
            status
        )
        
        # Keep table at reasonable size
        if packet_table.row_count > 100:
            packet_table.remove_row(packet_table.rows[0].key)
            
    def action_clear_threats(self):
        """Clear threat display"""
        threat_table = self.query_one(ThreatTable)
        threat_table.threats = []
        threat_table.refresh()
        self.notify("Threats cleared")
        
    def action_block_selected(self):
        """Block selected IP"""
        # TODO: Implement IP selection and blocking
        self.notify("Select an IP to block", severity="warning")
        
    def action_refresh(self):
        """Refresh all data"""
        self.update_stats()
        self.notify("Refreshed!")


def run_tui():
    """Run the TUI application"""
    app = NexusGuardTUI()
    app.run()


if __name__ == "__main__":
    run_tui()
