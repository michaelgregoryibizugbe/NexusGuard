"""
Database utility for NexusGuard
"""

import sqlite3
import os
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class Database:
    """SQLite database manager"""
    
    def __init__(self, db_path="nexusguard.db"):
        self.db_path = db_path
        self.conn = None
        self._init_db()
        
    def _init_db(self):
        """Initialize database and create tables"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            cursor = self.conn.cursor()
            
            # Threats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    description TEXT,
                    evidence TEXT,
                    recommendation TEXT,
                    blocked BOOLEAN DEFAULT 0
                )
            ''')
            
            # Packets table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    size INTEGER,
                    suspicious BOOLEAN DEFAULT 0
                )
            ''')
            
            # Blocked IPs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    severity TEXT,
                    blocked_at TEXT NOT NULL,
                    duration INTEGER DEFAULT 3600,
                    expired BOOLEAN DEFAULT 0
                )
            ''')
            
            # Stats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_packets INTEGER DEFAULT 0,
                    threats_detected INTEGER DEFAULT 0,
                    ips_blocked INTEGER DEFAULT 0,
                    tcp_packets INTEGER DEFAULT 0,
                    udp_packets INTEGER DEFAULT 0,
                    icmp_packets INTEGER DEFAULT 0
                )
            ''')
            
            self.conn.commit()
            logger.info("Database initialized")
            
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise
            
    def insert_threat(self, threat):
        """Insert a threat record"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO threats 
                (timestamp, type, severity, src_ip, dst_ip, description, evidence, recommendation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat.get('timestamp', datetime.now()).isoformat(),
                threat.get('type'),
                threat.get('severity'),
                threat.get('src_ip'),
                threat.get('dst_ip'),
                threat.get('description'),
                threat.get('evidence'),
                threat.get('recommendation')
            ))
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting threat: {e}")
            return None
            
    def insert_packet(self, packet):
        """Insert a packet record"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO packets 
                (timestamp, protocol, src_ip, dst_ip, src_port, dst_port, size, suspicious)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet.get('timestamp', datetime.now()).isoformat(),
                packet.get('protocol'),
                packet.get('src_ip'),
                packet.get('dst_ip'),
                packet.get('src_port'),
                packet.get('dst_port'),
                packet.get('size'),
                packet.get('suspicious', False)
            ))
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting packet: {e}")
            return None
            
    def insert_blocked_ip(self, ip, reason, severity, duration=3600):
        """Insert a blocked IP record"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips 
                (ip, reason, severity, blocked_at, duration)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                ip,
                reason,
                severity,
                datetime.now().isoformat(),
                duration
            ))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error inserting blocked IP: {e}")
            return False
            
    def get_recent_threats(self, limit=50):
        """Get recent threats"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM threats 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error fetching threats: {e}")
            return []
            
    def get_stats_summary(self):
        """Get stats summary"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_threats,
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
                FROM threats
            ''')
            row = cursor.fetchone()
            return dict(row) if row else {}
        except Exception as e:
            logger.error(f"Error fetching stats: {e}")
            return {}
            
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")
