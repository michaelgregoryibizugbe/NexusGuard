"""
Packet Capture Module - Captures and analyzes network packets
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from scapy.layers.http import HTTPRequest
import threading
from queue import Queue
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class PacketCapture:
    """High-performance packet capture and analysis"""
    
    def __init__(self, interface="eth0", callback=None):
        self.interface = interface
        self.callback = callback
        self.is_running = False
        self.packet_queue = Queue(maxsize=10000)
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_requests': 0,
            'suspicious': 0
        }
        self.thread = None
        
    def start(self):
        """Start packet capture"""
        if self.is_running:
            logger.warning("Packet capture already running")
            return
            
        self.is_running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        logger.info(f"Started packet capture on {self.interface}")
        
    def stop(self):
        """Stop packet capture"""
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=2)
        logger.info("Stopped packet capture")
        
    def _capture_loop(self):
        """Main capture loop"""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.is_running = False
            
    def _process_packet(self, packet):
        """Process individual packet"""
        try:
            self.stats['total_packets'] += 1
            
            packet_data = {
                'timestamp': datetime.now(),
                'size': len(packet),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'flags': None,
                'payload': None,
                'suspicious': False
            }
            
            # IP Layer
            if IP in packet:
                packet_data['src_ip'] = packet[IP].src
                packet_data['dst_ip'] = packet[IP].dst
                
            # TCP Layer
            if TCP in packet:
                packet_data['protocol'] = 'TCP'
                packet_data['src_port'] = packet[TCP].sport
                packet_data['dst_port'] = packet[TCP].dport
                packet_data['flags'] = packet[TCP].flags
                self.stats['tcp_packets'] += 1
                
                # Check for suspicious patterns
                if self._is_suspicious_tcp(packet):
                    packet_data['suspicious'] = True
                    self.stats['suspicious'] += 1
                    
            # UDP Layer
            elif UDP in packet:
                packet_data['protocol'] = 'UDP'
                packet_data['src_port'] = packet[UDP].sport
                packet_data['dst_port'] = packet[UDP].dport
                self.stats['udp_packets'] += 1
                
            # ICMP Layer
            elif ICMP in packet:
                packet_data['protocol'] = 'ICMP'
                self.stats['icmp_packets'] += 1
                
            # HTTP Layer
            if HTTPRequest in packet:
                self.stats['http_requests'] += 1
                packet_data['http_method'] = packet[HTTPRequest].Method.decode()
                packet_data['http_host'] = packet[HTTPRequest].Host.decode()
                packet_data['http_path'] = packet[HTTPRequest].Path.decode()
                
            # Add to queue
            if not self.packet_queue.full():
                self.packet_queue.put(packet_data)
                
            # Callback
            if self.callback:
                self.callback(packet_data)
                
        except Exception as e:
            logger.debug(f"Packet processing error: {e}")
            
    def _is_suspicious_tcp(self, packet):
        """Detect suspicious TCP patterns"""
        tcp = packet[TCP]
        
        # SYN flood detection
        if tcp.flags == 'S' and not tcp.flags == 'SA':
            return True
            
        # Port scanning detection (common scanning ports)
        scanning_ports = {22, 23, 80, 443, 3389, 8080, 8443}
        if tcp.dport in scanning_ports:
            return True
            
        # NULL scan
        if tcp.flags == 0:
            return True
            
        # XMAS scan
        if tcp.flags == 'FPU':
            return True
            
        return False
        
    def get_stats(self):
        """Get capture statistics"""
        return self.stats.copy()
        
    def get_packets(self, count=100):
        """Get recent packets from queue"""
        packets = []
        for _ in range(min(count, self.packet_queue.qsize())):
            try:
                packets.append(self.packet_queue.get_nowait())
            except:
                break
        return packets
