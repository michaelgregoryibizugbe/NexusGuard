"""
Threat Detection Module - AI/ML-powered threat detection
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging
import re

logger = logging.getLogger(__name__)


class ThreatDetector:
    """Advanced threat detection using ML and signatures"""
    
    # Threat severity levels
    SEVERITY = {
        'CRITICAL': 5,
        'HIGH': 4,
        'MEDIUM': 3,
        'LOW': 2,
        'INFO': 1
    }
    
    def __init__(self):
        self.ml_model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Tracking structures
        self.connection_tracker = defaultdict(lambda: deque(maxlen=100))
        self.threat_cache = deque(maxlen=1000)
        self.blocked_ips = set()
        
        # Attack signatures
        self.signatures = self._load_signatures()
        
        # Statistics
        self.stats = {
            'threats_detected': 0,
            'threats_blocked': 0,
            'false_positives': 0,
            'by_severity': defaultdict(int)
        }
        
    def _load_signatures(self):
        """Load attack signatures"""
        return {
            'sql_injection': [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"onerror\s*=",
                r"onload\s*=",
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"\%2e\%2e/",
            ],
            'command_injection': [
                r";\s*(ls|cat|wget|curl|nc|bash|sh)",
                r"\|\s*(ls|cat|wget|curl|nc|bash|sh)",
                r"`.*`",
            ]
        }
        
    def analyze_packet(self, packet_data):
        """Analyze packet for threats"""
        threats = []
        
        # Signature-based detection
        sig_threats = self._signature_detection(packet_data)
        threats.extend(sig_threats)
        
        # Anomaly detection
        if self.is_trained:
            anomaly_threat = self._anomaly_detection(packet_data)
            if anomaly_threat:
                threats.append(anomaly_threat)
                
        # Behavioral analysis
        behavioral_threats = self._behavioral_analysis(packet_data)
        threats.extend(behavioral_threats)
        
        # Rate limiting / DDoS detection
        ddos_threat = self._ddos_detection(packet_data)
        if ddos_threat:
            threats.append(ddos_threat)
            
        # Update statistics
        for threat in threats:
            self.stats['threats_detected'] += 1
            self.stats['by_severity'][threat['severity']] += 1
            self.threat_cache.append(threat)
            
        return threats
        
    def _signature_detection(self, packet_data):
        """Signature-based threat detection"""
        threats = []
        
        # Check HTTP payloads
        if 'http_path' in packet_data:
            path = packet_data['http_path']
            
            for attack_type, patterns in self.signatures.items():
                for pattern in patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        threats.append({
                            'type': attack_type.upper(),
                            'severity': 'HIGH',
                            'description': f'{attack_type.replace("_", " ").title()} attempt detected',
                            'src_ip': packet_data.get('src_ip'),
                            'dst_ip': packet_data.get('dst_ip'),
                            'timestamp': packet_data['timestamp'],
                            'evidence': f"Pattern: {pattern[:50]}",
                            'recommendation': f'Block source IP and investigate {attack_type}'
                        })
                        
        return threats
        
    def _anomaly_detection(self, packet_data):
        """ML-based anomaly detection"""
        try:
            # Extract features
            features = self._extract_features(packet_data)
            if features is None:
                return None
                
            # Predict
            features_scaled = self.scaler.transform([features])
            prediction = self.ml_model.predict(features_scaled)
            
            # -1 indicates anomaly
            if prediction[0] == -1:
                return {
                    'type': 'ANOMALY',
                    'severity': 'MEDIUM',
                    'description': 'Unusual network behavior detected',
                    'src_ip': packet_data.get('src_ip'),
                    'dst_ip': packet_data.get('dst_ip'),
                    'timestamp': packet_data['timestamp'],
                    'evidence': f"ML confidence: {self.ml_model.score_samples(features_scaled)[0]:.3f}",
                    'recommendation': 'Monitor source for additional suspicious activity'
                }
        except Exception as e:
            logger.debug(f"Anomaly detection error: {e}")
            
        return None
        
    def _behavioral_analysis(self, packet_data):
        """Analyze behavioral patterns"""
        threats = []
        src_ip = packet_data.get('src_ip')
        
        if not src_ip:
            return threats
            
        # Track connection
        self.connection_tracker[src_ip].append(packet_data)
        recent = list(self.connection_tracker[src_ip])
        
        # Port scanning detection
        if len(recent) >= 10:
            unique_ports = len(set(p.get('dst_port') for p in recent[-10:] if p.get('dst_port')))
            if unique_ports >= 7:  # Accessing 7+ different ports
                threats.append({
                    'type': 'PORT_SCAN',
                    'severity': 'HIGH',
                    'description': 'Port scanning activity detected',
                    'src_ip': src_ip,
                    'timestamp': packet_data['timestamp'],
                    'evidence': f'{unique_ports} unique ports accessed in short time',
                    'recommendation': 'Block source IP immediately'
                })
                
        # Rapid connection attempts (potential DDoS)
        if len(recent) >= 50:
            time_window = (recent[-1]['timestamp'] - recent[-50]['timestamp']).total_seconds()
            if time_window < 10:  # 50 packets in 10 seconds
                threats.append({
                    'type': 'RAPID_CONNECTIONS',
                    'severity': 'CRITICAL',
                    'description': 'Unusually high connection rate',
                    'src_ip': src_ip,
                    'timestamp': packet_data['timestamp'],
                    'evidence': f'{len(recent)} connections in {time_window:.1f}s',
                    'recommendation': 'Implement rate limiting or block source'
                })
                
        return threats
        
    def _ddos_detection(self, packet_data):
        """Detect DDoS attacks"""
        # SYN flood detection
        if packet_data.get('protocol') == 'TCP' and packet_data.get('flags') == 'S':
            src_ip = packet_data.get('src_ip')
            recent = list(self.connection_tracker[src_ip])
            
            # Count SYN packets in last 5 seconds
            five_sec_ago = datetime.now() - timedelta(seconds=5)
            syn_count = sum(1 for p in recent 
                          if p.get('flags') == 'S' and p['timestamp'] > five_sec_ago)
            
            if syn_count > 20:  # More than 20 SYN packets in 5 seconds
                return {
                    'type': 'SYN_FLOOD',
                    'severity': 'CRITICAL',
                    'description': 'SYN flood attack detected',
                    'src_ip': src_ip,
                    'timestamp': packet_data['timestamp'],
                    'evidence': f'{syn_count} SYN packets in 5 seconds',
                    'recommendation': 'Enable SYN cookies and block source'
                }
                
        return None
        
    def _extract_features(self, packet_data):
        """Extract features for ML model"""
        try:
            return [
                packet_data.get('size', 0),
                packet_data.get('src_port', 0),
                packet_data.get('dst_port', 0),
                1 if packet_data.get('protocol') == 'TCP' else 0,
                1 if packet_data.get('protocol') == 'UDP' else 0,
                1 if packet_data.get('suspicious', False) else 0,
            ]
        except:
            return None
            
    def train(self, training_data):
        """Train ML model with normal traffic"""
        try:
            features = [self._extract_features(p) for p in training_data]
            features = [f for f in features if f is not None]
            
            if len(features) < 10:
                logger.warning("Insufficient training data")
                return False
                
            # Scale and train
            self.scaler.fit(features)
            features_scaled = self.scaler.transform(features)
            self.ml_model.fit(features_scaled)
            self.is_trained = True
            
            logger.info(f"Model trained with {len(features)} samples")
            return True
        except Exception as e:
            logger.error(f"Training error: {e}")
            return False
            
    def get_recent_threats(self, count=50):
        """Get recent threats"""
        return list(self.threat_cache)[-count:]
        
    def get_stats(self):
        """Get detection statistics"""
        return {
            **self.stats,
            'model_trained': self.is_trained,
            'blocked_ips': len(self.blocked_ips)
        }
