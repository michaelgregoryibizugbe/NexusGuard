"""
Firewall Manager - Manages iptables rules and blocking
"""

import subprocess
import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class FirewallManager:
    """Manage firewall rules and IP blocking"""
    
    def __init__(self, auto_block=True):
        self.auto_block = auto_block
        self.blocked_ips = {}  # IP -> {timestamp, reason, threat_level}
        self.rules = []
        self.stats = {
            'blocks_added': 0,
            'blocks_removed': 0,
            'packets_dropped': 0
        }
        
        # Initialize chain
        self._init_chain()
        
    def _init_chain(self):
        """Initialize NexusGuard iptables chain"""
        try:
            # Create custom chain
            subprocess.run(
                ['iptables', '-N', 'NEXUSGUARD'],
                stderr=subprocess.DEVNULL
            )
            
            # Add chain to INPUT
            subprocess.run(
                ['iptables', '-I', 'INPUT', '-j', 'NEXUSGUARD'],
                stderr=subprocess.DEVNULL
            )
            
            logger.info("Firewall chain initialized")
        except Exception as e:
            logger.warning(f"Chain init warning: {e}")
            
    def block_ip(self, ip, reason="Threat detected", severity="MEDIUM", duration=3600):
        """Block an IP address"""
        try:
            if ip in self.blocked_ips:
                logger.debug(f"IP {ip} already blocked")
                return False
                
            # Add iptables rule
            result = subprocess.run(
                ['iptables', '-I', 'NEXUSGUARD', '-s', ip, '-j', 'DROP'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.blocked_ips[ip] = {
                    'timestamp': datetime.now(),
                    'reason': reason,
                    'severity': severity,
                    'duration': duration
                }
                self.stats['blocks_added'] += 1
                logger.info(f"Blocked IP: {ip} (Reason: {reason})")
                return True
            else:
                logger.error(f"Failed to block {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Block error: {e}")
            return False
            
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        try:
            if ip not in self.blocked_ips:
                logger.debug(f"IP {ip} not in block list")
                return False
                
            # Remove iptables rule
            result = subprocess.run(
                ['iptables', '-D', 'NEXUSGUARD', '-s', ip, '-j', 'DROP'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                del self.blocked_ips[ip]
                self.stats['blocks_removed'] += 1
                logger.info(f"Unblocked IP: {ip}")
                return True
            else:
                logger.error(f"Failed to unblock {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Unblock error: {e}")
            return False
            
    def block_port(self, port, protocol='tcp'):
        """Block a specific port"""
        try:
            subprocess.run(
                ['iptables', '-I', 'NEXUSGUARD', '-p', protocol, 
                 '--dport', str(port), '-j', 'DROP'],
                check=True
            )
            logger.info(f"Blocked port: {port}/{protocol}")
            return True
        except Exception as e:
            logger.error(f"Port block error: {e}")
            return False
            
    def get_blocked_ips(self):
        """Get list of blocked IPs"""
        return dict(self.blocked_ips)
        
    def cleanup_expired(self):
        """Remove expired blocks"""
        now = datetime.now()
        expired = []
        
        for ip, data in self.blocked_ips.items():
            age = (now - data['timestamp']).total_seconds()
            if age > data['duration']:
                expired.append(ip)
                
        for ip in expired:
            self.unblock_ip(ip)
            
        return len(expired)
        
    def get_stats(self):
        """Get firewall statistics"""
        return {
            **self.stats,
            'currently_blocked': len(self.blocked_ips)
        }
        
    def cleanup(self):
        """Clean up all rules"""
        try:
            # Flush our chain
            subprocess.run(['iptables', '-F', 'NEXUSGUARD'])
            
            # Remove from INPUT
            subprocess.run(
                ['iptables', '-D', 'INPUT', '-j', 'NEXUSGUARD'],
                stderr=subprocess.DEVNULL
            )
            
            # Delete chain
            subprocess.run(['iptables', '-X', 'NEXUSGUARD'])
            
            logger.info("Firewall cleanup complete")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
