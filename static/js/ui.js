// UI Manager for Huginn Network Profiler
class UIManager {
    constructor() {
        this.cacheElements();
        this.setupEventHandlers();
        this.init();
    }

    init() {
        this.hideEmptyState();
    }

    cacheElements() {
        this.totalProfilesElem = document.getElementById('totalProfiles');
        this.tcpProfilesElem = document.getElementById('tcpProfiles');
        this.httpProfilesElem = document.getElementById('httpProfiles');
        this.tlsProfilesElem = document.getElementById('tlsProfiles');
        this.completeProfilesElem = document.getElementById('completeProfiles');
        this.profilesListElem = document.getElementById('profilesList');
        this.profilesCountElem = document.getElementById('profilesCount');
        this.emptyStateElem = document.getElementById('emptyState');
        this.myProfileBtn = document.getElementById('myProfile');
        this.clearProfilesBtn = document.getElementById('clearProfiles');
        this.refreshProfilesBtn = document.getElementById('refreshProfiles');
        this.modal = document.getElementById('profileModal');
        this.modalTitle = document.getElementById('modalTitle');
        this.modalBody = document.getElementById('modalBody');
        this.modalCloseBtn = document.getElementById('modalClose');
    }

    setupEventHandlers() {
        this.myProfileBtn.addEventListener('click', () => this.showMyProfile());
        this.clearProfilesBtn.addEventListener('click', () => this.clearAllProfiles());
        this.refreshProfilesBtn.addEventListener('click', () => this.refreshProfiles());
        this.modalCloseBtn.addEventListener('click', () => this.closeModal());
        window.addEventListener('click', (event) => {
            if (event.target === this.modal) {
                this.closeModal();
            }
        });
    }

    updateStats(stats) {
        this.totalProfilesElem.textContent = stats.total_profiles || 0;
        this.tcpProfilesElem.textContent = stats.tcp_profiles || 0;
        this.httpProfilesElem.textContent = stats.http_profiles || 0;
        this.tlsProfilesElem.textContent = stats.tls_profiles || 0;
        this.completeProfilesElem.textContent = stats.complete_profiles || 0;
    }

    updateProfiles(profilesData) {
        const profiles = profilesData.profiles || {};
        const profilesArray = Object.entries(profiles).map(([key, value]) => ({ key, ...value }));
        
        this.profilesCountElem.textContent = `${profilesArray.length} profiles`;

        if (profilesArray.length === 0) {
            this.showEmptyState();
        } else {
            this.hideEmptyState();
            this.renderProfiles(profilesArray);
        }
    }

    renderProfiles(profiles) {
        this.profilesListElem.innerHTML = '';
        profiles.forEach(profile => {
            const card = this.createProfileCard(profile.key, profile);
            this.profilesListElem.appendChild(card);
        });
    }

    createProfileCard(key, profile) {
        const card = document.createElement('div');
        card.className = 'profile-card';
        card.dataset.key = key;

        const completeness = (profile.tcp_analysis ? 1 : 0) + (profile.http_analysis ? 1 : 0) + (profile.tls_analysis ? 1 : 0);
        const completenessClass = completeness === 3 ? 'complete' : (completeness === 2 ? 'partial' : 'incomplete');

        card.innerHTML = `
            <div class="profile-header">
                <div class="profile-ip">${key}</div>
                <div class="profile-timestamp">${new Date(profile.timestamp).toLocaleString()}</div>
            </div>
            <div class="profile-data">
                ${profile.tcp_analysis ? `<div class="data-section tcp"><div class="data-title">TCP</div><div class="data-content">${profile.tcp_analysis.os}</div></div>` : ''}
                ${profile.http_analysis ? `<div class="data-section http"><div class="data-title">HTTP</div><div class="data-content">${profile.http_analysis.browser}</div></div>` : ''}
                ${profile.tls_analysis ? `<div class="data-section tls"><div class="data-title">TLS</div><div class="data-content">${profile.tls_analysis.ja4}</div></div>` : ''}
            </div>
        `;

        card.addEventListener('click', () => this.showProfileModal(key, profile));
        return card;
    }

    showProfileModal(key, profile) {
        this.modalTitle.textContent = `Profile Details: ${key}`;
        this.modalBody.innerHTML = this.createDetailedProfileView(profile);
        this.modal.classList.add('active');
    }

    closeModal() {
        this.modal.classList.remove('active');
    }

    createDetailedProfileView(profile) {
        let tcpHtml = '<h4>TCP Signature</h4><p>Not captured</p>';
        if (profile.tcp_signature) {
            tcpHtml = `<h4>TCP Signature</h4><pre>${profile.tcp_signature}</pre>`;
        }

        let httpHtml = '<h4>HTTP Signature</h4><p>Not captured</p>';
        if (profile.http_signature) {
            httpHtml = `<h4>HTTP Signature</h4><pre>${profile.http_signature}</pre>`;
        }

        let tlsHtml = '<h4>TLS Fingerprint</h4><p>Not captured</p>';
        if (profile.tls_fingerprint) {
            tlsHtml = `<h4>TLS Fingerprint (JA4)</h4><pre>${profile.tls_fingerprint}</pre>`;
        }

        return `
            <div class="profile-details">
                <div class="detail-section">${tcpHtml}</div>
                <div class="detail-section">${httpHtml}</div>
                <div class="detail-section">${tlsHtml}</div>
            </div>
        `;
    }

    createDetailSection(title, data) {
        let content = '';
        for (const [key, value] of Object.entries(data)) {
            content += `<div class="detail-item">
                <div class="detail-label">${this.formatKey(key)}</div>
                <div class="detail-value">${typeof value === 'object' ? JSON.stringify(value, null, 2) : value}</div>
            </div>`;
        }
        return `<div class="detail-section"><h4>${title}</h4><div class="detail-grid">${content}</div></div>`;
    }
    
    formatKey(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    async showMyProfile() {
        try {
            const ip = await this.getClientIP();
            const profile = await window.huginnAPI.getProfile(ip);
            if (profile) {
                this.showProfileModal(ip, profile);
            } else {
                this.showError('Your profile has not been captured yet.');
            }
        } catch (error) {
            this.showError('Could not retrieve your profile.');
        }
    }

    async getClientIP() {
        try {
            // This is a simple way to get the public IP, but may not always be accurate
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            return data.ip;
        } catch (error) {
            console.error('Could not get public IP:', error);
            return null;
        }
    }

    showEmptyState() {
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
                this.refreshProfiles();
            } catch (error) {
                this.showError('Failed to clear profiles.');
            }
        }
    }

    async refreshProfiles() {
        try {
            await window.huginnApp.refresh();
            this.showSuccess('Profiles refreshed.');
        } catch (error) {
            this.showError('Failed to refresh profiles.');
        }
    }

    showError(message) {
        alert(`Error: ${message}`);
    }

    showSuccess(message) {
        alert(message);
    }
}

// Initialize UI Manager
window.uiManager = new UIManager(); 