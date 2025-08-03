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

        const tcpSignature = profile.tcp_signature ? this.formatObject(profile.tcp_signature) : 'Not captured';
        const httpSignature = profile.http_signature ? this.formatObject(profile.http_signature) : 'Not captured';
        const tlsFingerprint = profile.tls_fingerprint ? this.formatObject(profile.tls_fingerprint) : 'Not captured';

        this.profileDisplayElem.innerHTML = `
            <div class="profile-header">
                <div class="profile-ip">${profile.id}</div>
                <div class="profile-timestamp">Last seen: ${new Date(profile.last_seen).toLocaleString()}</div>
            </div>
            <div class="profile-data">
                <div class="data-section tcp">
                    <div class="data-title">TCP Signature</div>
                    <div class="data-content">${tcpSignature}</div>
                </div>
                <div class="data-section http">
                    <div class="data-title">HTTP Signature</div>
                    <div class="data-content">${httpSignature}</div>
                </div>
                <div class="data-section tls">
                    <div class="data-title">TLS Fingerprint (JA4)</div>
                    <div class="data-content">${tlsFingerprint}</div>
                </div>
            </div>
        `;
    }

    formatObject(obj) {
        return Object.entries(obj)
            .map(([key, value]) => `<strong>${this.formatKey(key)}:</strong> ${value}`)
            .join('<br>');
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