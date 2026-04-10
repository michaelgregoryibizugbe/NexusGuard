"""
Tests for PacketCapture module
"""

import unittest
from unittest.mock import patch, MagicMock
from queue import Queue
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Ether
from scapy.layers.http import HTTPRequest

from nexusguard.core.packet_capture import PacketCapture


class TestPacketCaptureInit(unittest.TestCase):
    """Test PacketCapture initialization"""

    def test_default_init(self):
        """Test default initialization"""
        pc = PacketCapture()
        self.assertEqual(pc.interface, "eth0")
        self.assertIsNone(pc.callback)
        self.assertFalse(pc.is_running)
        self.assertIsInstance(pc.packet_queue, Queue)
        self.assertEqual(pc.stats['total_packets'], 0)
        self.assertEqual(pc.stats['tcp_packets'], 0)
        self.assertEqual(pc.stats['udp_packets'], 0)
        self.assertEqual(pc.stats['icmp_packets'], 0)
        self.assertEqual(pc.stats['http_requests'], 0)
        self.assertEqual(pc.stats['suspicious'], 0)

    def test_custom_interface(self):
        """Test custom interface initialization"""
        pc = PacketCapture(interface="wlan0")
        self.assertEqual(pc.interface, "wlan0")

    def test_with_callback(self):
        """Test initialization with callback"""
        cb = MagicMock()
        pc = PacketCapture(callback=cb)
        self.assertEqual(pc.callback, cb)


class TestPacketCaptureStartStop(unittest.TestCase):
    """Test start/stop functionality"""

    @patch('nexusguard.core.packet_capture.threading.Thread')
    def test_start(self, mock_thread):
        """Test starting packet capture"""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        pc = PacketCapture()
        pc.start()

        self.assertTrue(pc.is_running)
        mock_thread.assert_called_once()
        self.assertEqual(pc.thread, mock_thread_instance)

    @patch('nexusguard.core.packet_capture.threading.Thread')
    def test_start_already_running(self, mock_thread):
        """Test starting when already running"""
        pc = PacketCapture()
        pc.is_running = True
        pc.start()

        mock_thread.assert_not_called()

    def test_stop(self):
        """Test stopping packet capture"""
        pc = PacketCapture()
        pc.is_running = True
        mock_thread = MagicMock()
        pc.thread = mock_thread

        pc.stop()

        self.assertFalse(pc.is_running)
        mock_thread.join.assert_called_once_with(timeout=2)


class TestProcessPacket(unittest.TestCase):
    """Test packet processing"""

    def test_process_tcp_packet(self):
        """Test processing a TCP packet"""
        pc = PacketCapture()

        # Create a mock TCP packet
        packet = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")

        pc._process_packet(packet)

        self.assertEqual(pc.stats['total_packets'], 1)
        self.assertEqual(pc.stats['tcp_packets'], 1)
        self.assertEqual(pc.stats['suspicious'], 1)  # SYN flag is suspicious
        self.assertFalse(pc.packet_queue.empty())

        packet_data = pc.packet_queue.get()
        self.assertEqual(packet_data['src_ip'], "192.168.1.1")
        self.assertEqual(packet_data['dst_ip'], "10.0.0.1")
        self.assertEqual(packet_data['src_port'], 12345)
        self.assertEqual(packet_data['dst_port'], 80)
        self.assertEqual(packet_data['protocol'], "TCP")
        self.assertTrue(packet_data['suspicious'])

    def test_process_udp_packet(self):
        """Test processing a UDP packet"""
        pc = PacketCapture()

        packet = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=53, dport=53)

        pc._process_packet(packet)

        self.assertEqual(pc.stats['total_packets'], 1)
        self.assertEqual(pc.stats['udp_packets'], 1)
        self.assertEqual(pc.stats['suspicious'], 0)

    def test_process_icmp_packet(self):
        """Test processing an ICMP packet"""
        pc = PacketCapture()

        packet = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / ICMP()

        pc._process_packet(packet)

        self.assertEqual(pc.stats['total_packets'], 1)
        self.assertEqual(pc.stats['icmp_packets'], 1)

    def test_process_packet_callback(self):
        """Test callback is invoked"""
        callback = MagicMock()
        pc = PacketCapture(callback=callback)

        packet = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=53, dport=53)

        pc._process_packet(packet)

        callback.assert_called_once()
        packet_data = callback.call_args[0][0]
        self.assertEqual(packet_data['src_ip'], "192.168.1.1")

    def test_process_packet_queue_full(self):
        """Test processing when queue is full"""
        pc = PacketCapture()
        pc.packet_queue = Queue(maxsize=1)
        pc.packet_queue.put({"test": "data"})

        packet = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=53, dport=53)

        pc._process_packet(packet)

        self.assertEqual(pc.stats['total_packets'], 1)
        # Queue should still have the original item since it was full
        self.assertEqual(pc.packet_queue.qsize(), 1)


class TestSuspiciousTCP(unittest.TestCase):
    """Test suspicious TCP detection"""

    def test_syn_only_packet(self):
        """Test SYN-only packet detection"""
        pc = PacketCapture()
        packet = Ether() / IP() / TCP(flags="S")

        self.assertTrue(pc._is_suspicious_tcp(packet))

    def test_syn_ack_not_suspicious(self):
        """Test SYN-ACK is not flagged as suspicious by SYN detection"""
        pc = PacketCapture()
        packet = Ether() / IP() / TCP(flags="SA")

        # SYN-ACK goes through port scanning check (port 0 not in scanning_ports)
        # Should return False since SA != S and port 0 not in scanning_ports
        self.assertFalse(pc._is_suspicious_tcp(packet))

    def test_scanning_port_detection(self):
        """Test detection of connections to scanning ports"""
        pc = PacketCapture()

        for port in [22, 23, 80, 443, 3389, 8080, 8443]:
            packet = Ether() / IP() / TCP(dport=port, flags="A")
            self.assertTrue(pc._is_suspicious_tcp(packet), f"Port {port} should be suspicious")

    def test_non_scanning_port(self):
        """Test non-scanning port is not flagged"""
        pc = PacketCapture()
        packet = Ether() / IP() / TCP(dport=9999, flags="A")

        self.assertFalse(pc._is_suspicious_tcp(packet))

    def test_null_scan(self):
        """Test NULL scan detection (no flags)"""
        pc = PacketCapture()
        packet = Ether() / IP() / TCP(flags=0)

        self.assertTrue(pc._is_suspicious_tcp(packet))

    def test_xmas_scan(self):
        """Test XMAS scan detection (FIN+PSH+URG)"""
        pc = PacketCapture()
        packet = Ether() / IP() / TCP(flags="FPU")

        self.assertTrue(pc._is_suspicious_tcp(packet))


class TestGetStatsAndPackets(unittest.TestCase):
    """Test get_stats and get_packets methods"""

    def test_get_stats(self):
        """Test getting statistics"""
        pc = PacketCapture()
        pc.stats['total_packets'] = 100
        pc.stats['tcp_packets'] = 50

        stats = pc.get_stats()

        self.assertEqual(stats['total_packets'], 100)
        self.assertEqual(stats['tcp_packets'], 50)
        # Should be a copy
        stats['total_packets'] = 999
        self.assertEqual(pc.stats['total_packets'], 100)

    def test_get_packets(self):
        """Test getting packets from queue"""
        pc = PacketCapture()

        # Add some packets to queue
        for i in range(5):
            pc.packet_queue.put({"packet_num": i})

        packets = pc.get_packets(count=3)

        self.assertEqual(len(packets), 3)
        self.assertEqual(packets[0]["packet_num"], 0)

    def test_get_packets_more_than_available(self):
        """Test getting more packets than available"""
        pc = PacketCapture()
        pc.packet_queue.put({"test": 1})

        packets = pc.get_packets(count=10)

        self.assertEqual(len(packets), 1)


if __name__ == '__main__':
    unittest.main()
