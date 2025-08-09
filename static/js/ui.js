// UI Manager for Huginn Network Profiler
class UIManager {
    constructor() {
        this.cacheElements();
        this.showEmptyState();
    }

    cacheElements() {
        this.profileDisplayElem = document.getElementById('profileDisplay');
        this.emptyStateElem = document.getElementById('emptyState');
        // The main find button is now controlled by app.js
    }

    displayProfile(profile) {
        if (!profile || Object.keys(profile).length === 0) {
            this.showEmptyState("Your profile could not be found or is empty. Please generate some traffic and try again.");
            return;
        }

        this.hideEmptyState();

        const tcpData = profile.tcp_client || profile.syn || profile.syn_ack || profile.mtu || profile.uptime ? this.formatTcpData(profile) : 'Not captured';
        const httpSignature = profile.http_signature ? this.formatObject(profile.http_signature) : 'Not captured';
        const tlsClient = profile.tls_client ? this.formatTlsClient(profile.tls_client) : 'Not captured';

        this.profileDisplayElem.innerHTML = `
            <div class="profile-header">
                <div class="profile-ip">${profile.id}</div>
                <div class="profile-timestamp">Last seen: ${new Date(profile.last_seen).toLocaleString()}</div>
            </div>
            <div class="profile-data">
                <div class="data-section tcp">
                    <div class="data-title">TCP</div>
                    <div class="data-content">${tcpData}</div>
                </div>
                <div class="data-section http">
                    <div class="data-title">HTTP Signature</div>
                    <div class="data-content">${httpSignature}</div>
                </div>
                <div class="data-section tls">
                    <div class="data-title">TLS Client</div>
                    <div class="data-content">${tlsClient}</div>
                </div>
            </div>
        `;
    }

    formatObject(obj) {
        return Object.entries(obj)
            .map(([key, value]) => `<strong>${this.formatKey(key)}:</strong> ${value}`)
            .join('<br>');
    }

    formatTcpData(profile) {
        const subcards = [];

        // SYN data (client)
        if (profile.syn) {
            subcards.push(this.formatTcpSubcard('SYN (Client)', profile.syn));
        }

        // SYN-ACK data (server)
        if (profile.syn_ack) {
            subcards.push(this.formatTcpSubcard('SYN-ACK (Server)', profile.syn_ack));
        }

        // MTU data
        if (profile.mtu) {
            subcards.push(this.formatTcpSubcard('MTU Detection', profile.mtu));
        }

        // Uptime data
        if (profile.uptime) {
            subcards.push(this.formatTcpSubcard('Uptime Detection', profile.uptime));
        }

        // TCP Client (compatibility)
        if (profile.tcp_client && !profile.syn) {
            subcards.push(this.formatTcpSubcard('TCP Client', profile.tcp_client));
        }

        return subcards.length > 0 ? subcards.join('') : 'No TCP data captured';
    }

    formatTcpSubcard(title, data) {
        return `<div class="tcp-subcard">
<div class="tcp-subcard-title">${title}</div>
<div class="tcp-subcard-content">
${this.formatTcpFields(data)}
</div>
</div>`;
    }

    formatTcpFields(data) {
        const fields = [];
        
        if (data.source) {
            fields.push(`<strong>Source:</strong> ${data.source.ip}:${data.source.port}`);
        }
        
        if (data.destination) {
            fields.push(`<strong>Destination:</strong> ${data.destination.ip}:${data.destination.port}`);
        }
        
        if (data.signature) {
            fields.push(`<strong>Signature:</strong> ${data.signature}`);
        }
        
        if (data.os_detected) {
            fields.push(`<strong>OS:</strong> ${data.os_detected.os} (Quality: ${data.os_detected.quality})`);
        }
        
        if (data.mtu_value) {
            fields.push(`<strong>MTU Value:</strong> ${data.mtu_value}`);
        }
        
        if (data.uptime_seconds) {
            const days = Math.floor(data.uptime_seconds / (24 * 3600));
            const hours = Math.floor((data.uptime_seconds % (24 * 3600)) / 3600);
            const minutes = Math.floor((data.uptime_seconds % 3600) / 60);
            fields.push(`<strong>Uptime:</strong> ${days}d ${hours}h ${minutes}m`);
        }
        
        if (data.details) {
            fields.push(`<strong>Version:</strong> ${data.details.version}`);
            fields.push(`<strong>TTL:</strong> ${data.details.initial_ttl}`);
            if (data.details.mss) {
                fields.push(`<strong>MSS:</strong> ${data.details.mss}`);
            }
            fields.push(`<strong>Window Size:</strong> ${data.details.window_size}`);
            if (data.details.window_scale) {
                fields.push(`<strong>Window Scale:</strong> ${data.details.window_scale}`);
            }
            if (data.details.options_layout) {
                fields.push(`<strong>Options:</strong> ${data.details.options_layout}`);
            }
            if (data.details.quirks) {
                fields.push(`<strong>Quirks:</strong> ${data.details.quirks}`);
            }
        }
        
        return fields.join('<br>');
    }

    formatTlsClient(tlsClient) {
        const allInfo = [
            `<strong>JA4 Hash:</strong> ${tlsClient.ja4}`,
            `<strong>JA4 Raw:</strong> ${tlsClient.ja4_raw}`,
            `<strong>JA4 Original:</strong> ${tlsClient.ja4_original}`,
            `<strong>JA4 Original Raw:</strong> ${tlsClient.ja4_original_raw}`,
            `<strong>Version:</strong> ${tlsClient.observed.version}`,
            `<strong>SNI:</strong> ${tlsClient.observed.sni || 'None'}`,
            `<strong>ALPN:</strong> ${tlsClient.observed.alpn || 'None'}`,
            `<strong>Cipher Suites:</strong> [${tlsClient.observed.cipher_suites.join(', ')}]`,
            `<strong>Extensions:</strong> [${tlsClient.observed.extensions.join(', ')}]`,
            `<strong>Signature Algorithms:</strong> [${tlsClient.observed.signature_algorithms.join(', ')}]`,
            `<strong>Elliptic Curves:</strong> [${tlsClient.observed.elliptic_curves.join(', ')}]`,
        ];

        return allInfo.join('<br>');
    }
    
    formatKey(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    showEmptyState(message = 'Click "Find My Network Profile" to begin.') {
        this.profileDisplayElem.innerHTML = '';
        const p = this.emptyStateElem.querySelector('p');
        if (p) {
            p.textContent = message;
        }
        this.emptyStateElem.style.display = 'flex';
    }

    hideEmptyState() {
        this.emptyStateElem.style.display = 'none';
    }

    clearAll() {
        this.showEmptyState();
    }
    
    showLoading() {
        const button = document.getElementById('findMyProfile');
        if (button) {
            button.disabled = true;
            button.textContent = 'Analyzing...';
        }
    }

    hideLoading() {
        const button = document.getElementById('findMyProfile');
        if (button) {
            button.disabled = false;
            button.textContent = 'Find My Network Profile';
        }
    }
    
    showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => {
            toast.remove();
        }, 3000);
    }

    showSuccess(message) {
        this.showToast(message, 'success');
    }

    showError(message) {
        this.showToast(message, 'error');
    }
} 