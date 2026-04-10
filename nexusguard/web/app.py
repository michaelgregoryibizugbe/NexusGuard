"""
Flask Web Application for NexusGuard
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time

from ..core.packet_capture import PacketCapture
from ..core.threat_detector import ThreatDetector
from ..core.firewall_manager import FirewallManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nexusguard-secret-key-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global instances
capture = None
detector = ThreatDetector()
firewall = FirewallManager()
is_running = False


def packet_callback(packet_data):
    """Callback for captured packets"""
    # Emit packet to web clients
    socketio.emit('packet', packet_data)
    
    # Analyze for threats
    threats = detector.analyze_packet(packet_data)
    
    for threat in threats:
        # Emit threat
        socketio.emit('threat', threat)
        
        # Auto-block if critical
        if threat['severity'] == 'CRITICAL' and threat.get('src_ip'):
            firewall.block_ip(
                threat['src_ip'],
                reason=threat['description'],
                severity=threat['severity']
            )


@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')


@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    stats = {
        'capture': capture.get_stats() if capture else {},
        'detector': detector.get_stats(),
        'firewall': firewall.get_stats()
    }
    return jsonify(stats)


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    emit('stats', {
        'capture': capture.get_stats() if capture else {},
        'detector': detector.get_stats(),
        'firewall': firewall.get_stats()
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f"Client disconnected: {request.sid}")


@socketio.on('start-protection')
def handle_start():
    """Start protection"""
    global capture, is_running
    
    if not is_running:
        capture = PacketCapture(interface="eth0", callback=packet_callback)
        capture.start()
        is_running = True
        emit('status', {'protection': True, 'message': 'Protection started'})


@socketio.on('stop-protection')
def handle_stop():
    """Stop protection"""
    global capture, is_running
    
    if is_running and capture:
        capture.stop()
        is_running = False
        emit('status', {'protection': False, 'message': 'Protection stopped'})


@socketio.on('block-ip')
def handle_block_ip(data):
    """Block an IP address"""
    ip = data.get('ip')
    if ip:
        success = firewall.block_ip(ip, reason="Manual block")
        emit('status', {
            'success': success,
            'message': f"Blocked {ip}" if success else f"Failed to block {ip}"
        })


@socketio.on('get-stats')
def handle_get_stats():
    """Get current statistics"""
    emit('stats', {
        'total_packets': capture.get_stats()['total_packets'] if capture else 0,
        'threats_detected': detector.get_stats()['threats_detected'],
        'blocked_ips': firewall.get_stats()['currently_blocked']
    })


def run_web(host='0.0.0.0', port=8080):
    """Run the web application"""
    print(f"""
    ╔═══════════════════════════════════════════╗
    ║  🛡️  NexusGuard Web Interface Started   ║
    ║                                           ║
    ║  URL: http://{host}:{port}              ║
    ║                                           ║
    ║  Press Ctrl+C to stop                     ║
    ╚═══════════════════════════════════════════╝
    """)
    
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    run_web()
