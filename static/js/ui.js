// UI Manager for Huginn Network Profiler
class UIManager {
    constructor() {
        this.cacheElements();
        this.setupEventHandlers();
        this.init();
    }

    init() {
        this.showEmptyState();
    }

    cacheElements() {
        this.profileDisplayElem = document.getElementById('profileDisplay');
        this.emptyStateElem = document.getElementById('emptyState');
        this.myProfileBtn = document.getElementById('myProfileBtn');
        this.clearProfilesBtn = document.getElementById('clearProfilesBtn');
    }

    setupEventHandlers() {
        this.myProfileBtn.addEventListener('click', () => this.showMyProfile());
        this.clearProfilesBtn.addEventListener('click', () => this.clearAllProfiles());
    }

    renderProfile(key, profile) {
        if (!profile) {
            this.showEmptyState("Your profile has not been captured yet. Please generate some traffic and try again.");
            return;
        }

        this.hideEmptyState();

        const tcpSignature = profile.tcp_signature ? this.formatSignature(profile.tcp_signature) : 'Not captured';
        const httpSignature = profile.http_signature ? this.formatSignature(profile.http_signature) : 'Not captured';
        const tlsFingerprint = profile.tls_fingerprint ? this.formatSignature(profile.tls_fingerprint) : 'Not captured';

        this.profileDisplayElem.innerHTML = `
            <div class="profile-header">
                <div class="profile-ip">${key}</div>
                <div class="profile-timestamp">${new Date(profile.timestamp).toLocaleString()}</div>
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

    formatSignature(signature) {
        // Basic formatting for readability
        return signature.replace(/,/g, ',<br>').replace(/;/g, ';<br>');
    }

    async showMyProfile() {
        this.myProfileBtn.disabled = true;
        this.myProfileBtn.textContent = 'Analyzing...';
        try {
            const ip = await this.getClientIP();
            if (!ip) {
                this.showError('Could not determine your IP address.');
                return;
            }
            const profile = await window.huginnAPI.getProfile(ip);
            this.renderProfile(ip, profile);
        } catch (error) {
            console.error('Failed to get your profile:', error);
            this.showError('Could not retrieve your profile. The backend might be down.');
            this.showEmptyState('Could not retrieve your profile.');
        } finally {
            this.myProfileBtn.disabled = false;
            this.myProfileBtn.textContent = 'Find My Network Profile';
        }
    }

    async getClientIP() {
        try {
            // Using a reliable public IP service
            const response = await fetch('https://api.ipify.org?format=json');
            if (!response.ok) throw new Error('Failed to fetch IP');
            const data = await response.json();
            return data.ip;
        } catch (error) {
            console.error('Could not get public IP:', error);
            // Fallback for local testing
            return '127.0.0.1';
        }
    }

    showEmptyState(message = 'Click "Find My Network Profile" to begin.') {
        this.profileDisplayElem.innerHTML = '';
        const p = this.emptyStateElem.querySelector('p');
        p.textContent = message;
        this.emptyStateElem.style.display = 'flex';
    }

    hideEmptyState() {
        this.emptyStateElem.style.display = 'none';
    }

    async clearAllProfiles() {
        if (confirm('Are you sure you want to delete all profiles?')) {
            try {
                await window.huginnAPI.clearProfiles();
                this.showSuccess('All profiles cleared.');
                this.showEmptyState();
            } catch (error) {
                this.showError('Failed to clear profiles.');
            }
        }
    }

    showError(message) {
        // A more noticeable error display
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-toast';
        errorDiv.textContent = `Error: ${message}`;
        document.body.appendChild(errorDiv);
        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }
    
    showSuccess(message) {
        // A simple success message display
        const successDiv = document.createElement('div');
        successDiv.className = 'success-toast';
        successDiv.textContent = message;
        document.body.appendChild(successDiv);
        setTimeout(() => {
            successDiv.remove();
        }, 3000);
    }
}

// Initialize UI Manager
window.uiManager = new UIManager(); 