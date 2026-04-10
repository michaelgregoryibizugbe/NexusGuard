"""
NexusGuard - Advanced IPS/IDS System
"""

__version__ = "1.0.0"
__author__ = "Security Team"
__license__ = "MIT"

from .core.packet_capture import PacketCapture
from .core.threat_detector import ThreatDetector
from .core.firewall_manager import FirewallManager

__all__ = [
    "PacketCapture",
    "ThreatDetector",
    "FirewallManager",
]
