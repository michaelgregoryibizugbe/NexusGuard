// NexusGuard Web UI - Main JavaScript

class NexusGuardUI {
    constructor() {
        this.socket = null;
        this.charts = {};
        this.protectionEnabled = false;
        this.commands = [
            { name: 'Enable Protection', action: 'enable-protection', icon: '🛡️' },
            { name: 'Disable Protection', action: 'disable-protection', icon: '⏸️' },
            { name: 'Clear Threats', action: 'clear-threats', icon: '🧹' },
            { name: 'Refresh Stats', action: 'refresh-stats', icon: '🔄' },
            { name: 'Export Logs', action: 'export-logs', icon: '💾' },
            { name: 'Block IP', action: 'block-ip', icon: '🚫' },
        ];
        
        this.init();
    }
    
    init() {
        this.initSocket();
        this.initCharts();
        this.initEventListeners();
        this.initCommandPalette();
        this.startStatsUpdate();
    }
    
    initSocket() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            this.showToast('Connected to NexusGuard', 'success');
        });
        
        this.socket.on('packet', (data) => {
            this.addPacketToFeed(data);
            this.updateStats(data);
        });
        
        this.socket.on('threat', (data) => {
            this.addThreat(data);
            this.showToast(`⚠️ ${data.type} detected from ${data.src_ip}`, 'warning');
        });
        
        this.socket.on('stats', (data) => {
            this.updateDashboardStats(data);
        });
    }
    
    initCharts() {
        // Traffic Chart
        const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
        this.charts.traffic = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'TCP',
                        data: [],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'UDP',
                        data: [],
                        borderColor: '#764ba2',
                        backgroundColor: 'rgba(118, 75, 162, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Other',
                        data: [],
                        borderColor: '#f093fb',
                        backgroundColor: 'rgba(240, 147, 251, 0.1)',
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#f8fafc' }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#64748b' },
                        grid: { color: 'rgba(99, 102, 241, 0.1)' }
                    },
                    x: {
                        ticks: { color: '#64748b' },
                        grid: { color: 'rgba(99, 102, 241, 0.1)' }
                    }
                }
            }
        });
        
        // Threat Chart
        const threatCtx = document.getElementById('threat-chart').getContext('2d');
        this.charts.threats = new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: ['SQL Injection', 'XSS', 'Port Scan', 'DDoS', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#667eea',
                        '#764ba2',
                        '#f093fb',
                        '#f5576c',
                        '#4facfe'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#f8fafc' }
                    }
                }
            }
        });
    }
    
    initEventListeners() {
        // Protection toggle
        document.getElementById('toggle-protection').addEventListener('click', () => {
            this.toggleProtection();
        });
        
        // Clear threats
        document.getElementById('clear-threats').addEventListener('click', () => {
            this.clearThreats();
        });
        
        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.filterPackets(e.target.dataset.filter);
            });
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl+K for command palette
            if (e.ctrlKey && e.key === 'k') {
                e.preventDefault();
                this.toggleCommandPalette();
            }
            
            // Escape to close command palette
            if (e.key === 'Escape') {
                this.closeCommandPalette();
            }
        });
    }
    
    initCommandPalette() {
        const input = document.getElementById('command-input');
        const suggestions = document.getElementById('command-suggestions');
        
        input.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const filtered = this.commands.filter(cmd => 
                cmd.name.toLowerCase().includes(query)
            );
            
            suggestions.innerHTML = filtered.map(cmd => `
                <div class="command-item" data-action="${cmd.action}">
                    <span>${cmd.icon}</span> ${cmd.name}
                </div>
            `).join('');
            
            // Add click handlers
            suggestions.querySelectorAll('.command-item').forEach(item => {
                item.addEventListener('click', () => {
                    this.executeCommand(item.dataset.action);
                    this.closeCommandPalette();
                });
            });
        });
        
        // Trigger initial display
        input.dispatchEvent(new Event('input'));
    }
    
    toggleCommandPalette() {
        const palette = document.getElementById('command-palette');
        palette.classList.toggle('active');
        
        if (palette.classList.contains('active')) {
            document.getElementById('command-input').focus();
        }
    }
    
    closeCommandPalette() {
        document.getElementById('command-palette').classList.remove('active');
        document.getElementById('command-input').value = '';
    }
    
    executeCommand(action) {
        const actions = {
            'enable-protection': () => this.toggleProtection(true),
            'disable-protection': () => this.toggleProtection(false),
            'clear-threats': () => this.clearThreats(),
            'refresh-stats': () => this.refreshStats(),
            'export-logs': () => this.exportLogs(),
            'block-ip': () => this.promptBlockIP()
        };
        
        if (actions[action]) {
            actions[action]();
        }
    }
    
    toggleProtection(force = null) {
        this.protectionEnabled = force !== null ? force : !this.protectionEnabled;
        
        const btn = document.getElementById('toggle-protection');
        const statusDot = document.getElementById('protection-status');
        
        if (this.protectionEnabled) {
            btn.textContent = '🛡️ Protection Active';
            btn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
            statusDot.classList.add('active');
            this.socket.emit('start-protection');
            this.showToast('Protection enabled', 'success');
        } else {
            btn.textContent = '⏸️ Enable Protection';
            btn.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
            statusDot.classList.remove('active');
            this.socket.emit('stop-protection');
            this.showToast('Protection disabled', 'warning');
        }
    }
    
    addPacketToFeed(packet) {
        const feed = document.getElementById('packet-feed');
        const isSuspicious = packet.suspicious;
        
        const packetEl = document.createElement('div');
        packetEl.className = `packet-item ${isSuspicious ? 'suspicious' : ''}`;
        packetEl.innerHTML = `
            <div class="packet-info">
                <span class="packet-time">${new Date(packet.timestamp).toLocaleTimeString()}</span>
                <span><strong>${packet.protocol}</strong></span>
                <span>${packet.src_ip}:${packet.src_port || ''}</span>
                <span>→</span>
                <span>${packet.dst_ip}:${packet.dst_port || ''}</span>
                <span>${packet.size} bytes</span>
            </div>
            <span>${isSuspicious ? '⚠️' : '✅'}</span>
        `;
        
        feed.insertBefore(packetEl, feed.firstChild);
        
        // Keep only last 50 packets
        while (feed.children.length > 50) {
            feed.removeChild(feed.lastChild);
        }
    }
    
    addThreat(threat) {
        const tbody = document.getElementById('threats-tbody');
        
        // Remove "no data" row if exists
        const noData = tbody.querySelector('.no-data');
        if (noData) noData.remove();
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${new Date(threat.timestamp).toLocaleTimeString()}</td>
            <td><strong>${threat.type}</strong></td>
            <td><span class="severity-badge severity-${threat.severity.toLowerCase()}">${threat.severity}</span></td>
            <td><code>${threat.src_ip || 'N/A'}</code></td>
            <td>${threat.description}</td>
            <td>
                <button class="btn btn-sm" onclick="ui.blockIP('${threat.src_ip}')">🚫 Block</button>
            </td>
        `;
        
        tbody.insertBefore(row, tbody.firstChild);
        
        // Keep only last 20 threats
        while (tbody.children.length > 20) {
            tbody.removeChild(tbody.lastChild);
        }
    }
    
    blockIP(ip) {
        if (confirm(`Block IP ${ip}?`)) {
            this.socket.emit('block-ip', { ip });
            this.showToast(`Blocked ${ip}`, 'success');
        }
    }
    
    clearThreats() {
        document.getElementById('threats-tbody').innerHTML = `
            <tr class="no-data">
                <td colspan="6">No threats detected yet. Protection is working! ✨</td>
            </tr>
        `;
        this.showToast('Threats cleared', 'success');
    }
    
    updateDashboardStats(data) {
        document.getElementById('stat-packets').textContent = data.total_packets.toLocaleString();
        document.getElementById('stat-threats').textContent = data.threats_detected;
        document.getElementById('stat-blocked').textContent = data.blocked_ips;
    }
    
    updateStats(packet) {
        const now = new Date().toLocaleTimeString();
        
        // Update traffic chart
        if (this.charts.traffic.data.labels.length > 20) {
            this.charts.traffic.data.labels.shift();
            this.charts.traffic.data.datasets.forEach(ds => ds.data.shift());
        }
        
        this.charts.traffic.data.labels.push(now);
        this.charts.traffic.data.datasets[0].data.push(packet.protocol === 'TCP' ? 1 : 0);
        this.charts.traffic.data.datasets[1].data.push(packet.protocol === 'UDP' ? 1 : 0);
        this.charts.traffic.data.datasets[2].data.push(packet.protocol === 'ICMP' ? 1 : 0);
        this.charts.traffic.update('none');
    }
    
    filterPackets(filter) {
        const packets = document.querySelectorAll('.packet-item');
        
        packets.forEach(packet => {
            const protocol = packet.querySelector('strong').textContent;
            const isSuspicious = packet.classList.contains('suspicious');
            
            let show = true;
            if (filter === 'tcp') show = protocol === 'TCP';
            else if (filter === 'udp') show = protocol === 'UDP';
            else if (filter === 'suspicious') show = isSuspicious;
            
            packet.style.display = show ? 'flex' : 'none';
        });
    }
    
    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
    
    refreshStats() {
        this.socket.emit('get-stats');
        this.showToast('Stats refreshed', 'success');
    }
    
    exportLogs() {
        this.showToast('Exporting logs...', 'info');
        // Implementation for log export
    }
    
    promptBlockIP() {
        const ip = prompt('Enter IP address to block:');
        if (ip) {
            this.blockIP(ip);
        }
    }
    
    startStatsUpdate() {
        setInterval(() => {
            this.socket.emit('get-stats');
        }, 5000);
    }
}

// Initialize UI
const ui = new NexusGuardUI();
