// UI Manager for Huginn Network Profiler
class UIManager {
    constructor() {
        this.elements = {};
        this.currentProfiles = new Map();
        this.currentFilter = 'all';
        this.searchQuery = '';
        this.isModalOpen = false;
        this.myProfileMode = false;
        this.myProfileData = null;
        this.activityFeed = [];
        this.maxActivityItems = 100;
        
        this.init();
    }

    // Initialize UI elements and event handlers
    init() {
        this.cacheElements();
        this.setupEventHandlers();
        this.updateConnectionStatus(false);
        this.showEmptyState();
    }

    // Cache DOM elements
    cacheElements() {
        this.elements = {
            // Header elements
            statusIndicator: document.getElementById('statusIndicator'),
            statusText: document.getElementById('statusText'),
            toggleConnection: document.getElementById('toggleConnection'),
            
            // Stats elements
            totalProfiles: document.getElementById('totalProfiles'),
            tcpProfiles: document.getElementById('tcpProfiles'),
            httpProfiles: document.getElementById('httpProfiles'),
            tlsProfiles: document.getElementById('tlsProfiles'),
            completeProfiles: document.getElementById('completeProfiles'),
            ja4ValidatedProfiles: document.getElementById('ja4ValidatedProfiles'),
            ja4ConsistentProfiles: document.getElementById('ja4ConsistentProfiles'),
            ja4SuspiciousProfiles: document.getElementById('ja4SuspiciousProfiles'),
            
            // Controls elements
            searchInput: document.getElementById('searchInput'),
            searchBtn: document.getElementById('searchBtn'),
            filterType: document.getElementById('filterType'),
            myProfile: document.getElementById('myProfile'),
            clearProfiles: document.getElementById('clearProfiles'),
            refreshProfiles: document.getElementById('refreshProfiles'),
            
            // Profiles elements
            profilesCount: document.getElementById('profilesCount'),
            profilesList: document.getElementById('profilesList'),
            emptyState: document.getElementById('emptyState'),
            startCollector: document.getElementById('startCollector'),
            
            // Activity elements
            activityFeed: document.getElementById('activityFeed'),
            clearActivity: document.getElementById('clearActivity'),
            
            // Modal elements
            profileModal: document.getElementById('profileModal'),
            modalTitle: document.getElementById('modalTitle'),
            modalBody: document.getElementById('modalBody'),
            modalClose: document.getElementById('modalClose')
        };
    }

    // Setup event handlers
    setupEventHandlers() {
        // Connection toggle
        this.elements.toggleConnection?.addEventListener('click', () => {
            this.toggleConnection();
        });

        // Search functionality
        this.elements.searchBtn?.addEventListener('click', () => {
            this.performSearch();
        });

        this.elements.searchInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.performSearch();
            }
        });

        // Filter functionality
        this.elements.filterType?.addEventListener('change', (e) => {
            this.currentFilter = e.target.value;
            this.exitMyProfileMode();
            this.filterProfiles();
        });

        this.elements.myProfile?.addEventListener('click', () => {
            this.showMyProfile();
        });

        this.elements.clearProfiles?.addEventListener('click', () => {
            this.clearAllProfiles();
        });

        this.elements.refreshProfiles?.addEventListener('click', () => {
            this.refreshProfiles();
        });

        this.elements.startCollector?.addEventListener('click', () => {
            this.startCollector();
        });

        // Activity controls
        this.elements.clearActivity?.addEventListener('click', () => {
            this.clearActivity();
        });

        // Modal controls
        this.elements.modalClose?.addEventListener('click', () => {
            this.closeModal();
        });

        this.elements.profileModal?.addEventListener('click', (e) => {
            if (e.target === this.elements.profileModal) {
                this.closeModal();
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isModalOpen) {
                this.closeModal();
            }
        });
    }

    // Update connection status
    updateConnectionStatus(connected) {
        if (!this.elements.statusIndicator || !this.elements.statusText || !this.elements.toggleConnection) {
            return;
        }

        if (connected) {
            this.elements.statusIndicator.className = 'status-indicator connected';
            this.elements.statusText.textContent = 'Connected';
            this.elements.toggleConnection.textContent = 'Disconnect';
        } else {
            this.elements.statusIndicator.className = 'status-indicator';
            this.elements.statusText.textContent = 'Disconnected';
            this.elements.toggleConnection.textContent = 'Connect';
        }
    }

    // Update connection status with connecting state
    updateConnectionStatusConnecting() {
        if (!this.elements.statusIndicator || !this.elements.statusText) {
            return;
        }

        this.elements.statusIndicator.className = 'status-indicator connecting';
        this.elements.statusText.textContent = 'Connecting...';
    }

    // Toggle connection
    toggleConnection() {
        if (window.wsManager.isConnected) {
            window.wsManager.disconnect();
        } else {
            this.updateConnectionStatusConnecting();
            window.wsManager.connect();
        }
    }

    // Update statistics
    updateStats(stats) {
        if (!stats) return;

        if (this.elements.totalProfiles) {
            this.elements.totalProfiles.textContent = stats.total_profiles || 0;
        }
        if (this.elements.tcpProfiles) {
            this.elements.tcpProfiles.textContent = stats.tcp_profiles || 0;
        }
        if (this.elements.httpProfiles) {
            this.elements.httpProfiles.textContent = stats.http_profiles || 0;
        }
        if (this.elements.tlsProfiles) {
            this.elements.tlsProfiles.textContent = stats.tls_profiles || 0;
        }
        if (this.elements.completeProfiles) {
            this.elements.completeProfiles.textContent = stats.complete_profiles || 0;
        }
        if (this.elements.ja4ValidatedProfiles) {
            this.elements.ja4ValidatedProfiles.textContent = stats.ja4_validated_profiles || 0;
        }
        if (this.elements.ja4ConsistentProfiles) {
            this.elements.ja4ConsistentProfiles.textContent = stats.ja4_consistent_profiles || 0;
        }
        if (this.elements.ja4SuspiciousProfiles) {
            this.elements.ja4SuspiciousProfiles.textContent = stats.ja4_suspicious_profiles || 0;
        }
    }

    // Update profiles display
    updateProfiles(profilesData) {
        if (!profilesData || !profilesData.profiles) {
            this.showEmptyState();
            return;
        }

        const profiles = profilesData.profiles;
        const profileCount = Object.keys(profiles).length;

        // Update profiles count
        if (this.elements.profilesCount) {
            this.elements.profilesCount.textContent = `${profileCount} profile${profileCount !== 1 ? 's' : ''}`;
        }

        // Store current profiles
        this.currentProfiles.clear();
        for (const [key, profile] of Object.entries(profiles)) {
            this.currentProfiles.set(key, profile);
        }

        if (profileCount === 0) {
            this.showEmptyState();
        } else {
            this.hideEmptyState();
            
            // If in My Profile mode, maintain the filter
            if (this.myProfileMode && this.myProfileData) {
                // Update my profile data if it exists in new data
                const myProfileKey = Object.keys(this.myProfileData)[0];
                if (profiles[myProfileKey]) {
                    this.myProfileData[myProfileKey] = profiles[myProfileKey];
                }
                this.renderProfiles(this.myProfileData);
            } else {
                this.renderProfiles(profiles);
            }
        }
    }

    // Render profiles list
    renderProfiles(profiles) {
        if (!this.elements.profilesList) return;

        const profilesArray = Object.entries(profiles);
        const filteredProfiles = this.applyCurrentFilters(profilesArray);

        this.elements.profilesList.innerHTML = '';

        filteredProfiles.forEach(([key, profile]) => {
            const profileCard = this.createProfileCard(key, profile);
            this.elements.profilesList.appendChild(profileCard);
        });
    }

    // Create profile card element
    createProfileCard(key, profile) {
        const card = document.createElement('div');
        card.className = 'profile-card';
        card.dataset.profileKey = key;

        const timestamp = new Date().toLocaleString(); // TcpInfo doesn't have timestamp
        const completeness = 1.0; // TcpInfo doesn't have completeness

        card.innerHTML = `
            <div class="profile-header">
                <div class="profile-ip">${key}</div>
                <div class="profile-timestamp">${timestamp}</div>
            </div>
            <div class="profile-data">
                ${this.createRawDataSections(profile)}
                <div class="data-section">
                    <div class="data-title">Profile Analysis</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">Quality Score:</span>
                            <span class="data-value">${completeness.toFixed(2)}</span>
                        </div>
                        ${this.createJA4ValidationInfo(profile)}
                    </div>
                </div>
            </div>
        `;

        card.addEventListener('click', () => {
            this.showProfileModal(key, profile);
        });

        return card;
    }

    // Create JA4 validation information for a profile
    createJA4ValidationInfo(profile) {
        if (!profile) return '';

                 // Debug: Log profile structure for the first profile
        if (Math.random() < 0.1) { // Only log 10% of the time to avoid spam
            console.log('🔍 Profile structure:', {
                profile_keys: Object.keys(profile),
                tls_client: profile.tls_client ? 'exists' : 'undefined',
                http_request: profile.http_request ? 'exists' : 'undefined',
                ja4_validation: profile.ja4_validation ? 'exists' : 'undefined',
                tls_client_ja4: profile?.tls_client?.ja4,
                http_user_agent: profile?.http_request?.user_agent,
                validation_result: profile?.ja4_validation?.is_consistent
            });
        }

        // Check if we have JA4 validation data
        const hasJA4Data = this.hasJA4ValidationData(profile);
        
        if (!hasJA4Data) {
            return `
                <div class="data-item">
                    <span class="data-label">JA4 Status:</span>
                    <span class="data-value ja4-status-none">No JA4 Data</span>
                </div>
            `;
        }

        // Extract JA4 validation result
        const ja4Result = this.extractJA4ValidationResult(profile);
        
        return `
            <div class="data-item">
                <span class="data-label">JA4 Status:</span>
                <span class="data-value ja4-status-${ja4Result.status}">${ja4Result.icon} ${ja4Result.text}</span>
            </div>
        `;
    }

    // Check if profile has JA4 validation data
    hasJA4ValidationData(profile) {
        // Check for JA4 data in the actual structure
        return (profile?.tls_client?.ja4) ||
               (profile?.tls?.ja4);
    }

    // Extract JA4 validation result from profile
    extractJA4ValidationResult(profile) {
        // Check if we have actual validation results from the backend
        if (profile?.ja4_validation) {
            const validation = profile.ja4_validation;
            
            if (validation.is_consistent) {
                return {
                    status: 'consistent',
                    icon: '✅',
                    text: `Consistent (${(validation.confidence * 100).toFixed(0)}%)`
                };
            } else {
                const anomalyCount = validation.anomalies ? validation.anomalies.length : 0;
                return {
                    status: 'suspicious',
                    icon: '⚠️',
                    text: `Suspicious (${anomalyCount} anomalies)`
                };
            }
        }

                 // Fallback logic if no validation results available
        const hasUserAgent = (profile?.http_request?.user_agent) ||
                           (profile?.http?.request?.user_agent);

        const hasJA4 = this.hasJA4ValidationData(profile);

        if (hasJA4 && hasUserAgent) {
            return {
                status: 'validated',
                icon: '🔍',
                text: 'Validated (pending analysis)'
            };
        } else if (hasJA4 && !hasUserAgent) {
            return {
                status: 'validated',
                icon: '🔍',
                text: 'JA4 only'
            };
        } else {
            return {
                status: 'validated',
                icon: '🔍',
                text: 'Validated'
            };
        }
    }

    // Create data sections for TcpInfo structure (matching user's example)
    createRawDataSections(tcpInfo) {
        if (!tcpInfo) return '';

        let html = '';

        // SYN packet (client data)
        if (tcpInfo.syn) {
            const synData = tcpInfo.syn;
            html += `
                <div class="data-section syn-client">
                    <div class="data-title">📥 SYN Packet (Client)</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">OS:</span>
                            <span class="data-value">${synData.os || 'Unknown'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Quality:</span>
                            <span class="data-value">${synData.quality || 'N/A'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Distance:</span>
                            <span class="data-value">${synData.dist || 'N/A'}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        // SYN-ACK packet (server data)
        if (tcpInfo.syn_ack) {
            const synAckData = tcpInfo.syn_ack;
            html += `
                <div class="data-section syn-server">
                    <div class="data-title">📤 SYN-ACK Packet (Server)</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">OS:</span>
                            <span class="data-value">${synAckData.os || 'Unknown'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Quality:</span>
                            <span class="data-value">${synAckData.quality || 'N/A'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Distance:</span>
                            <span class="data-value">${synAckData.dist || 'N/A'}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        // HTTP request (client data)
        if (tcpInfo.http_request) {
            const httpReq = tcpInfo.http_request;
            html += `
                <div class="data-section http-client">
                    <div class="data-title">🌐📥 HTTP Request (Client)</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">Browser:</span>
                            <span class="data-value">${httpReq.browser || 'Unknown'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">User-Agent:</span>
                            <span class="data-value">${httpReq.user_agent ? httpReq.user_agent.substring(0, 50) + '...' : 'Unknown'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Quality:</span>
                            <span class="data-value">${httpReq.quality || 'N/A'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Language:</span>
                            <span class="data-value">${httpReq.lang || 'Unknown'}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        // HTTP response (server data)
        if (tcpInfo.http_response) {
            const httpRes = tcpInfo.http_response;
            html += `
                <div class="data-section http-server">
                    <div class="data-title">🌐📤 HTTP Response (Server)</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">Web Server:</span>
                            <span class="data-value">${httpRes.web_server || 'Unknown'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Quality:</span>
                            <span class="data-value">${httpRes.quality || 'N/A'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Diagnosis:</span>
                            <span class="data-value">${httpRes.diagnosis || 'Unknown'}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        // TLS client (client data)
        if (tcpInfo.tls_client) {
            const tlsClient = tcpInfo.tls_client;
            html += `
                <div class="data-section tls-client">
                    <div class="data-title">🔒 TLS Client</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">JA4:</span>
                            <span class="data-value">${tlsClient.ja4 ? tlsClient.ja4.substring(0, 20) + '...' : 'Unknown'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Version:</span>
                            <span class="data-value">${tlsClient.observed?.version || 'Unknown'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">SNI:</span>
                            <span class="data-value">${tlsClient.observed?.sni || 'None'}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        // MTU data
        if (tcpInfo.mtu) {
            const mtuData = tcpInfo.mtu;
            html += `
                <div class="data-section mtu-data">
                    <div class="data-title">📏 MTU Data</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">MTU:</span>
                            <span class="data-value">${mtuData.mtu || 'Unknown'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Link:</span>
                            <span class="data-value">${mtuData.link || 'Unknown'}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        // Uptime data
        if (tcpInfo.uptime) {
            const uptimeData = tcpInfo.uptime;
            html += `
                <div class="data-section uptime-data">
                    <div class="data-title">⏱️ Uptime Data</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">Uptime:</span>
                            <span class="data-value">${uptimeData.time || 'Unknown'}</span>
                        </div>
                        <div class="data-item">
                            <span class="data-label">Frequency:</span>
                            <span class="data-value">${uptimeData.freq || 'Unknown'}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        return html || '<div class="data-section"><div class="data-title">No Data Available</div></div>';
    }

    // Create legacy TCP summary for profile card
    createLegacyTcpSummary(profile) {
        if (!profile.tcp_client && !profile.tcp_server && !profile.tcp) {
            return '';
        }

        let html = `
            <div class="data-section tcp-summary">
                <div class="data-title">🔗 TCP Summary (Legacy)</div>
                <div class="data-content">
        `;

        if (profile.tcp_client) {
            html += `
                <div class="data-item">
                    <span class="data-label">🔵 Client (SYN):</span>
                    <span class="data-value">${profile.tcp_client.os} (Q:${profile.tcp_client.quality.toFixed(2)})</span>
                </div>
            `;
        }

        if (profile.tcp_server) {
            html += `
                <div class="data-item">
                    <span class="data-label">🔶 Server (SYN-ACK):</span>
                    <span class="data-value">${profile.tcp_server.os} (Q:${profile.tcp_server.quality.toFixed(2)})</span>
                </div>
            `;
        }

        if (profile.tcp && !profile.tcp_client && !profile.tcp_server) {
            // Fallback for old tcp field
            html += `
                <div class="data-item">
                    <span class="data-label">📊 General:</span>
                    <span class="data-value">${profile.tcp.os} (Q:${profile.tcp.quality.toFixed(2)})</span>
                </div>
            `;
        }

        html += `
                </div>
            </div>
        `;

        return html;
    }

    // Create data section for profile card
    createDataSection(title, data, type) {
        if (!data) {
            return `
                <div class="data-section ${type}">
                    <div class="data-title">${title}</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">Status:</span>
                            <span class="data-value">No data</span>
                        </div>
                    </div>
                </div>
            `;
        }

        let content = '';
        const maxItems = 3;
        let itemCount = 0;

        for (const [key, value] of Object.entries(data)) {
            if (itemCount >= maxItems) break;
            
            let displayValue = value;
            if (typeof value === 'object' && value !== null) {
                displayValue = JSON.stringify(value).substring(0, 50) + '...';
            } else if (typeof value === 'string' && value.length > 30) {
                displayValue = value.substring(0, 30) + '...';
            }

            content += `
                <div class="data-item">
                    <span class="data-label">${this.formatKey(key)}:</span>
                    <span class="data-value">${displayValue}</span>
                </div>
            `;
            itemCount++;
        }

        return `
            <div class="data-section ${type}">
                <div class="data-title">${title}</div>
                <div class="data-content">
                    ${content}
                </div>
            </div>
        `;
    }

    // Create HTTP Request section for profile card
    createHttpRequestSection(httpData) {
        if (!httpData || !httpData.request) {
            return '';
        }

        let content = '';
        const maxItems = 3;
        let itemCount = 0;

        for (const [key, value] of Object.entries(httpData.request)) {
            if (itemCount >= maxItems) break;
            
            let displayValue = value;
            if (typeof value === 'object' && value !== null) {
                displayValue = JSON.stringify(value).substring(0, 50) + '...';
            } else if (typeof value === 'string' && value.length > 30) {
                displayValue = value.substring(0, 30) + '...';
            }

            content += `
                <div class="data-item">
                    <span class="data-label">${this.formatKey(key)}:</span>
                    <span class="data-value">${displayValue}</span>
                </div>
            `;
            itemCount++;
        }

        if (content) {
            return `
                <div class="data-section http-request">
                    <div class="data-title">HTTP Request</div>
                    <div class="data-content">
                        ${content}
                    </div>
                </div>
            `;
        }
        return '';
    }

    // Create HTTP Response section for profile card
    createHttpResponseSection(httpData) {
        if (!httpData || !httpData.response) {
            return '';
        }

        let content = '';
        const maxItems = 3;
        let itemCount = 0;

        for (const [key, value] of Object.entries(httpData.response)) {
            if (itemCount >= maxItems) break;
            
            let displayValue = value;
            if (typeof value === 'object' && value !== null) {
                displayValue = JSON.stringify(value).substring(0, 50) + '...';
            } else if (typeof value === 'string' && value.length > 30) {
                displayValue = value.substring(0, 30) + '...';
            }

            content += `
                <div class="data-item">
                    <span class="data-label">${this.formatKey(key)}:</span>
                    <span class="data-value">${displayValue}</span>
                </div>
            `;
            itemCount++;
        }

        if (content) {
            return `
                <div class="data-section http-response">
                    <div class="data-title">HTTP Response</div>
                    <div class="data-content">
                        ${content}
                    </div>
                </div>
            `;
        }
        return '';
    }

    // Format key for display
    formatKey(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    // Show profile modal
    showProfileModal(key, profile) {
        if (!this.elements.profileModal) return;

        this.elements.modalTitle.textContent = `Profile Details - ${key}`;
        this.elements.modalBody.innerHTML = this.createDetailedProfileView(profile);
        this.elements.profileModal.classList.add('active');
        this.isModalOpen = true;
    }

    // Close modal
    closeModal() {
        if (!this.elements.profileModal) return;

        this.elements.profileModal.classList.remove('active');
        this.isModalOpen = false;
    }

    // Create detailed profile view
    createDetailedProfileView(profile) {
        let html = '<div class="profile-details">';

        // Basic info
        html += `
            <div class="detail-section">
                <h4>Basic Information</h4>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Source IP:</span>
                        <span class="detail-value">${profile.source_ip || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Timestamp:</span>
                        <span class="detail-value">${new Date().toLocaleString()}</span>
                    </div>
                </div>
            </div>
        `;

        // TcpInfo data sections
        html += this.createTcpInfoDetailSections(profile);

        html += '</div>';
        return html;
    }

    // Create detailed TcpInfo sections for modal
    createTcpInfoDetailSections(tcpInfo) {
        let html = '';

        // SYN packet (client data)
        if (tcpInfo.syn) {
            const synData = tcpInfo.syn;
            html += `
                <div class="detail-section">
                    <h4>📥 SYN Packet (Client Data)</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">OS:</span>
                                <span class="detail-value">${synData.os || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Quality:</span>
                                <span class="detail-value">${synData.quality || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Distance:</span>
                                <span class="detail-value">${synData.dist || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Signature:</span>
                                <span class="detail-value">${synData.signature || 'Unknown'}</span>
                            </div>
                        </div>
                        ${this.createTcpObservedDetails(synData.observed)}
                    </div>
                </div>
            `;
        }

        // SYN-ACK packet (server data)
        if (tcpInfo.syn_ack) {
            const synAckData = tcpInfo.syn_ack;
            html += `
                <div class="detail-section">
                    <h4>📤 SYN-ACK Packet (Server Data)</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">OS:</span>
                                <span class="detail-value">${synAckData.os || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Quality:</span>
                                <span class="detail-value">${synAckData.quality || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Distance:</span>
                                <span class="detail-value">${synAckData.dist || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Signature:</span>
                                <span class="detail-value">${synAckData.signature || 'Unknown'}</span>
                            </div>
                        </div>
                        ${this.createTcpObservedDetails(synAckData.observed)}
                    </div>
                </div>
            `;
        }

        // HTTP request (client data)
        if (tcpInfo.http_request) {
            const httpReq = tcpInfo.http_request;
            html += `
                <div class="detail-section">
                    <h4>🌐📥 HTTP Request (Client Data)</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Browser:</span>
                                <span class="detail-value">${httpReq.browser || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">User-Agent:</span>
                                <span class="detail-value">${httpReq.user_agent || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Quality:</span>
                                <span class="detail-value">${httpReq.quality || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Language:</span>
                                <span class="detail-value">${httpReq.lang || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Diagnosis:</span>
                                <span class="detail-value">${httpReq.diagnosis || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Signature:</span>
                                <span class="detail-value">${httpReq.signature || 'Unknown'}</span>
                            </div>
                        </div>
                        ${this.createHttpObservedDetails(httpReq.observed)}
                    </div>
                </div>
            `;
        }

        // HTTP response (server data)
        if (tcpInfo.http_response) {
            const httpRes = tcpInfo.http_response;
            html += `
                <div class="detail-section">
                    <h4>🌐📤 HTTP Response (Server Data)</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Web Server:</span>
                                <span class="detail-value">${httpRes.web_server || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Quality:</span>
                                <span class="detail-value">${httpRes.quality || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Diagnosis:</span>
                                <span class="detail-value">${httpRes.diagnosis || 'Unknown'}</span>
                            </div>
                        </div>
                        ${this.createHttpObservedDetails(httpRes.observed)}
                    </div>
                </div>
            `;
        }

        // TLS client data
        if (tcpInfo.tls_client) {
            const tlsClient = tcpInfo.tls_client;
            html += `
                <div class="detail-section">
                    <h4>🔒 TLS Client Data</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">JA4:</span>
                                <span class="detail-value">${tlsClient.ja4 || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">JA4 Raw:</span>
                                <span class="detail-value">${tlsClient.ja4_raw || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">JA4 Original:</span>
                                <span class="detail-value">${tlsClient.ja4_original || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">JA4 Original Raw:</span>
                                <span class="detail-value">${tlsClient.ja4_original_raw || 'Unknown'}</span>
                            </div>
                        </div>
                        ${this.createTlsObservedDetails(tlsClient.observed)}
                    </div>
                </div>
            `;
        }

        // MTU data
        if (tcpInfo.mtu) {
            const mtuData = tcpInfo.mtu;
            html += `
                <div class="detail-section">
                    <h4>📏 MTU Data</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">MTU:</span>
                                <span class="detail-value">${mtuData.mtu || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Link:</span>
                                <span class="detail-value">${mtuData.link || 'Unknown'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        // Uptime data
        if (tcpInfo.uptime) {
            const uptimeData = tcpInfo.uptime;
            html += `
                <div class="detail-section">
                    <h4>⏱️ Uptime Data</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Uptime:</span>
                                <span class="detail-value">${uptimeData.time || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Frequency:</span>
                                <span class="detail-value">${uptimeData.freq || 'Unknown'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        return html;
    }

    // Helper methods for creating observed details
    createTcpObservedDetails(observed) {
        if (!observed) return '';
        return `
            <div class="detail-subsection">
                <h6>TCP Observed Details</h6>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Version:</span>
                        <span class="detail-value">${observed.version || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">ITTL:</span>
                        <span class="detail-value">${observed.ittl || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Options Length:</span>
                        <span class="detail-value">${observed.olen || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">MSS:</span>
                        <span class="detail-value">${observed.mss || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Window Size:</span>
                        <span class="detail-value">${observed.wsize || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Window Scale:</span>
                        <span class="detail-value">${observed.wscale || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Options Layout:</span>
                        <span class="detail-value">${observed.olayout || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Quirks:</span>
                        <span class="detail-value">${observed.quirks || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Payload Class:</span>
                        <span class="detail-value">${observed.pclass || 'Unknown'}</span>
                    </div>
                </div>
            </div>
        `;
    }

    createHttpObservedDetails(observed) {
        if (!observed) return '';
        return `
            <div class="detail-subsection">
                <h6>HTTP Observed Details</h6>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Version:</span>
                        <span class="detail-value">${observed.version || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Header Order:</span>
                        <span class="detail-value">${observed.horder || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Headers Absent:</span>
                        <span class="detail-value">${observed.habsent || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Expected Software:</span>
                        <span class="detail-value">${observed.expsw || 'Unknown'}</span>
                    </div>
                </div>
            </div>
        `;
    }

    createTlsObservedDetails(observed) {
        if (!observed) return '';
        return `
            <div class="detail-subsection">
                <h6>TLS Observed Details</h6>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Version:</span>
                        <span class="detail-value">${observed.version || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">SNI:</span>
                        <span class="detail-value">${observed.sni || 'None'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">ALPN:</span>
                        <span class="detail-value">${observed.alpn || 'None'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Cipher Suites:</span>
                        <span class="detail-value">${observed.cipher_suites ? observed.cipher_suites.join(', ') : 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Extensions:</span>
                        <span class="detail-value">${observed.extensions ? observed.extensions.join(', ') : 'Unknown'}</span>
                    </div>
                </div>
            </div>
        `;
    }

    // Create detailed raw data sections for modal
    createRawDataDetailSections(rawData) {
        let html = '';

        // SYN packet (client data)
        if (rawData.syn) {
            const synData = rawData.syn;
            html += `
                <div class="detail-section">
                    <h4>📥 SYN Packet (Client Data)</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Source:</span>
                                <span class="detail-value">${synData.source?.ip || 'Unknown'}:${synData.source?.port || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">OS Detected:</span>
                                <span class="detail-value">${synData.os_detected?.os || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Quality:</span>
                                <span class="detail-value">${synData.os_detected?.quality?.toFixed(2) || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Distance:</span>
                                <span class="detail-value">${synData.os_detected?.distance || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Signature:</span>
                                <span class="detail-value">${synData.signature || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Timestamp:</span>
                                <span class="detail-value">${synData.timestamp || 'Unknown'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        // SYN-ACK packet (server data)
        if (rawData.syn_ack) {
            const synAckData = rawData.syn_ack;
            html += `
                <div class="detail-section">
                    <h4>📤 SYN-ACK Packet (Server Data)</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Source (Server):</span>
                                <span class="detail-value">${synAckData.source?.ip || 'Unknown'}:${synAckData.source?.port || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Destination (Client):</span>
                                <span class="detail-value">${synAckData.destination?.ip || 'Unknown'}:${synAckData.destination?.port || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">OS Detected:</span>
                                <span class="detail-value">${synAckData.os_detected?.os || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Quality:</span>
                                <span class="detail-value">${synAckData.os_detected?.quality?.toFixed(2) || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Distance:</span>
                                <span class="detail-value">${synAckData.os_detected?.distance || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Signature:</span>
                                <span class="detail-value">${synAckData.signature || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Timestamp:</span>
                                <span class="detail-value">${synAckData.timestamp || 'Unknown'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        // HTTP request (client data)
        if (rawData.http_request) {
            const httpReq = rawData.http_request;
            html += `
                <div class="detail-section">
                    <h4>🌐📥 HTTP Request (Client Data)</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">User-Agent:</span>
                                <span class="detail-value">${httpReq.user_agent || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Method:</span>
                                <span class="detail-value">${httpReq.method || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Host:</span>
                                <span class="detail-value">${httpReq.host || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Accept:</span>
                                <span class="detail-value">${httpReq.accept || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Accept-Language:</span>
                                <span class="detail-value">${httpReq.accept_language || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Accept-Encoding:</span>
                                <span class="detail-value">${httpReq.accept_encoding || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Connection:</span>
                                <span class="detail-value">${httpReq.connection || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Quality:</span>
                                <span class="detail-value">${httpReq.quality?.toFixed(2) || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Signature:</span>
                                <span class="detail-value">${httpReq.signature || 'Unknown'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        // HTTP response (server data)
        if (rawData.http_response) {
            const httpRes = rawData.http_response;
            html += `
                <div class="detail-section">
                    <h4>🌐📤 HTTP Response (Server Data)</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Server:</span>
                                <span class="detail-value">${httpRes.server || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Status:</span>
                                <span class="detail-value">${httpRes.status || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Content-Type:</span>
                                <span class="detail-value">${httpRes.content_type || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Content-Length:</span>
                                <span class="detail-value">${httpRes.content_length || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Set-Cookie:</span>
                                <span class="detail-value">${httpRes.set_cookie || 'None'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Cache-Control:</span>
                                <span class="detail-value">${httpRes.cache_control || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Quality:</span>
                                <span class="detail-value">${httpRes.quality?.toFixed(2) || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Signature:</span>
                                <span class="detail-value">${httpRes.signature || 'Unknown'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        // TLS client (client data)
        if (rawData.tls_client) {
            const tlsClient = rawData.tls_client;
            html += `
                <div class="detail-section">
                    <h4>🔒 TLS Client (Client Data)</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Source:</span>
                                <span class="detail-value">${tlsClient.source?.ip || 'Unknown'}:${tlsClient.source?.port || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">JA4:</span>
                                <span class="detail-value">${tlsClient.ja4 || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">JA4 Raw:</span>
                                <span class="detail-value">${tlsClient.ja4_raw || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Version:</span>
                                <span class="detail-value">${tlsClient.details?.version || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">SNI:</span>
                                <span class="detail-value">${tlsClient.details?.sni || 'None'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">ALPN:</span>
                                <span class="detail-value">${tlsClient.details?.alpn || 'None'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Cipher Suites:</span>
                                <span class="detail-value">${tlsClient.details?.cipher_suites?.join(', ') || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Extensions:</span>
                                <span class="detail-value">${tlsClient.details?.extensions?.join(', ') || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Timestamp:</span>
                                <span class="detail-value">${tlsClient.timestamp || 'Unknown'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        // MTU data
        if (rawData.mtu) {
            const mtuData = rawData.mtu;
            html += `
                <div class="detail-section">
                    <h4>📏 MTU Data</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Source:</span>
                                <span class="detail-value">${mtuData.source?.ip || 'Unknown'}:${mtuData.source?.port || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">MTU Value:</span>
                                <span class="detail-value">${mtuData.mtu_value || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Timestamp:</span>
                                <span class="detail-value">${mtuData.timestamp || 'Unknown'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        // Uptime data
        if (rawData.uptime) {
            const uptimeData = rawData.uptime;
            const uptimeHours = Math.floor(uptimeData.uptime_seconds / 3600);
            const uptimeMinutes = Math.floor((uptimeData.uptime_seconds % 3600) / 60);
            const uptimeSeconds = uptimeData.uptime_seconds % 60;
            
            html += `
                <div class="detail-section">
                    <h4>⏱️ Uptime Data</h4>
                    <div class="detail-subsection">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Source:</span>
                                <span class="detail-value">${uptimeData.source?.ip || 'Unknown'}:${uptimeData.source?.port || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Uptime:</span>
                                <span class="detail-value">${uptimeHours}h ${uptimeMinutes}m ${uptimeSeconds}s</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Uptime Seconds:</span>
                                <span class="detail-value">${uptimeData.uptime_seconds || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Timestamp:</span>
                                <span class="detail-value">${uptimeData.timestamp || 'Unknown'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        return html;
    }

    // Create detail section
    createDetailSection(title, data) {
        let html = `
            <div class="detail-section">
                <h4>${title}</h4>
                <div class="detail-grid">
        `;

        for (const [key, value] of Object.entries(data)) {
            const displayValue = typeof value === 'object' ? 
                JSON.stringify(value, null, 2) : 
                String(value);

            html += `
                <div class="detail-item">
                    <span class="detail-label">${this.formatKey(key)}:</span>
                    <span class="detail-value">${displayValue}</span>
                </div>
            `;
        }

        html += '</div></div>';
        return html;
    }

    // Apply current filters
    applyCurrentFilters(profilesArray) {
        let filtered = profilesArray;

        // Apply type filter
        if (this.currentFilter !== 'all') {
            filtered = filtered.filter(([key, profile]) => {
                switch (this.currentFilter) {
                    case 'tcp':
                        return profile.tcp;
                    case 'http':
                        return profile.http;
                    case 'tls':
                        return profile.tls;
                    case 'complete':
                        return profile.metadata?.completeness >= 1.0;
                    default:
                        return true;
                }
            });
        }

        // Apply search filter
        if (this.searchQuery) {
            const query = this.searchQuery.toLowerCase();
            filtered = filtered.filter(([key, profile]) => {
                return key.toLowerCase().includes(query) ||
                       JSON.stringify(profile).toLowerCase().includes(query);
            });
        }

        return filtered;
    }

    // Filter profiles
    filterProfiles() {
        const profiles = Object.fromEntries(this.currentProfiles);
        this.renderProfiles(profiles);
    }

    // Perform search
    performSearch() {
        if (!this.elements.searchInput) return;

        this.searchQuery = this.elements.searchInput.value.trim();
        
        // Exit My Profile mode unless the search is specifically for "My Profile"
        if (!this.searchQuery.startsWith('My Profile')) {
            this.exitMyProfileMode();
        }
        
        this.filterProfiles();
    }

    // Show only my profile
    async showMyProfile() {
        try {
            // Get both public and local IPs
            const publicIP = await this.getPublicIP();
            const localIP = await this.getLocalIP();
            
            const candidateIPs = [publicIP, localIP].filter(Boolean);
            
            if (candidateIPs.length === 0) {
                alert('❌ Could not detect any IP address');
                return;
            }

            // Check if we have profiles
            if (!this.currentProfiles || this.currentProfiles.size === 0) {
                alert('❌ No profiles available yet.\n\nMake sure the collector is running and you\'ve generated some network traffic first.');
                return;
            }

            // Find my profile using any candidate IP
            const profilesObject = Object.fromEntries(this.currentProfiles);
            
            let myProfile = null;
            let matchedIP = null;
            
            // Try to find exact matches first
            for (const candidateIP of candidateIPs) {
                myProfile = Object.entries(profilesObject).find(([key, profile]) => {
                    return key === candidateIP || profile.source_ip === candidateIP;
                });
                if (myProfile) {
                    matchedIP = candidateIP;
                    break;
                }
            }
            
            // If no exact match, try partial matches
            if (!myProfile) {
                for (const candidateIP of candidateIPs) {
                    myProfile = Object.entries(profilesObject).find(([key, profile]) => {
                        return key.includes(candidateIP) || candidateIP.includes(key) ||
                               (profile.source_ip && (profile.source_ip.includes(candidateIP) || candidateIP.includes(profile.source_ip)));
                    });
                    if (myProfile) {
                        matchedIP = candidateIP;
                        break;
                    }
                }
            }

            if (!myProfile) {
                // Offer manual selection
                const profileKeys = Object.keys(profilesObject);
                const manualChoice = confirm(`❌ No automatic match found for your IPs: ${candidateIPs.join(', ')}\n\nAvailable profiles: ${profileKeys.join(', ')}\n\nWould you like to manually select your profile?`);
                
                if (manualChoice && profileKeys.length > 0) {
                    // For now, let's assume the user wants the first local IP profile
                    const localProfile = profileKeys.find(key => key.startsWith('192.168.') || key.startsWith('10.') || key.startsWith('172.'));
                    if (localProfile) {
                        myProfile = [localProfile, profilesObject[localProfile]];
                        matchedIP = localProfile;
                    } else {
                        alert('❌ No suitable local profile found.');
                        return;
                    }
                } else {
                    return;
                }
            }

            // Activate My Profile mode
            this.myProfileMode = true;
            this.myProfileData = { [myProfile[0]]: myProfile[1] };
            
            // Show only my profile
            this.renderProfiles(this.myProfileData);
            
            // Update UI indicators
            if (this.elements.filterType) {
                this.elements.filterType.value = 'all'; // Reset filter dropdown
            }
            
            if (this.elements.searchInput) {
                this.elements.searchInput.value = `My Profile (${myProfile[0]})`;
            }
            
            // Update My Profile button to show active state
            if (this.elements.myProfile) {
                this.elements.myProfile.textContent = '👤 My Profile (Active)';
                this.elements.myProfile.classList.add('btn-active');
            }
            
        } catch (error) {
            console.error('Error showing my profile:', error);
            alert('❌ Error detecting your profile. Please try again.');
        }
    }

    // Exit My Profile mode and return to normal view
    exitMyProfileMode() {
        if (this.myProfileMode) {
            this.myProfileMode = false;
            this.myProfileData = null;
            
            // Reset search input if it was showing "My Profile"
            if (this.elements.searchInput && this.elements.searchInput.value.startsWith('My Profile')) {
                this.elements.searchInput.value = '';
                this.searchQuery = '';
            }
            
            // Reset My Profile button to normal state
            if (this.elements.myProfile) {
                this.elements.myProfile.textContent = '👤 My Profile';
                this.elements.myProfile.classList.remove('btn-active');
            }
        }
    }

    // Get public IP address
    async getPublicIP() {
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            return data.ip || null;
        } catch (error) {
            return null;
        }
    }

    // Get client IP address (try both public and local)
    async getClientIP() {
        const publicIP = await this.getPublicIP();
        if (publicIP) return publicIP;
        
        const localIP = await this.getLocalIP();
        return localIP;
    }

    // Get local IP using WebRTC
    getLocalIP() {
        return new Promise((resolve) => {
            const pc = new RTCPeerConnection({
                iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
            });

            let resolved = false;
            pc.createDataChannel('');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));

            pc.onicecandidate = (event) => {
                if (event.candidate && !resolved) {
                    const candidate = event.candidate.candidate;
                    
                    // Look for IPv4 addresses
                    const ipMatch = candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
                    if (ipMatch) {
                        const ip = ipMatch[1];
                        // Skip localhost and weird IPs
                        if (ip !== '127.0.0.1' && !ip.startsWith('169.254.')) {
                            resolved = true;
                            pc.close();
                            resolve(ip);
                        }
                    }
                }
            };

            // Timeout after 5 seconds
            setTimeout(() => {
                if (!resolved) {
                    pc.close();
                    resolve(null);
                }
            }, 5000);
        });
    }

    // Show empty state
    showEmptyState() {
        if (this.elements.emptyState) {
            this.elements.emptyState.style.display = 'flex';
        }
        if (this.elements.profilesList) {
            this.elements.profilesList.style.display = 'none';
        }
    }

    // Hide empty state
    hideEmptyState() {
        if (this.elements.emptyState) {
            this.elements.emptyState.style.display = 'none';
        }
        if (this.elements.profilesList) {
            this.elements.profilesList.style.display = 'block';
        }
    }

    // Clear all profiles
    async clearAllProfiles() {
        if (confirm('Are you sure you want to clear all profiles?')) {
            try {
                await window.huginnAPI.clearProfiles();
                this.addActivity('Cleared all profiles', 'removed');
                this.refreshProfiles();
            } catch (error) {
                console.error('Failed to clear profiles:', error);
                this.showError('Failed to clear profiles');
            }
        }
    }

    // Refresh profiles
    async refreshProfiles() {
        try {
            this.exitMyProfileMode();
            
            const profiles = await window.huginnAPI.getProfiles();
            this.updateProfiles(profiles);
            
            const stats = await window.huginnAPI.getStats();
            this.updateStats(stats);
        } catch (error) {
            console.error('Failed to refresh profiles:', error);
            this.showError('Failed to refresh profiles');
        }
    }

    // Start collector
    startCollector() {
        this.addActivity('Collector start requested', 'created');
        // This would typically trigger the collector via API
        // For now, we'll just show a message
        alert('Collector would be started here. This requires backend implementation.');
    }

    // Add activity item
    addActivity(message, type = 'created') {
        const activity = {
            message,
            type,
            timestamp: new Date().toISOString()
        };

        this.activityFeed.unshift(activity);
        
        // Limit activity feed size
        if (this.activityFeed.length > this.maxActivityItems) {
            this.activityFeed = this.activityFeed.slice(0, this.maxActivityItems);
        }

        this.renderActivity();
    }

    // Render activity feed
    renderActivity() {
        if (!this.elements.activityFeed) return;

        this.elements.activityFeed.innerHTML = '';

        this.activityFeed.forEach(activity => {
            const item = document.createElement('div');
            item.className = 'activity-item';
            
            const time = new Date(activity.timestamp).toLocaleTimeString();
            
            item.innerHTML = `
                <div class="activity-message">
                    <span class="activity-type ${activity.type}">${activity.type}</span>
                    ${activity.message}
                </div>
                <div class="activity-time">${time}</div>
            `;

            this.elements.activityFeed.appendChild(item);
        });
    }

    // Clear activity
    clearActivity() {
        this.activityFeed = [];
        this.renderActivity();
    }

    // Show error message
    showError(message) {
        // Simple error display - could be enhanced with toast notifications
        console.error(message);
        alert(message);
    }

    // Show success message
    showSuccess(message) {
        // Simple success display - could be enhanced with toast notifications
        console.log(message);
    }
}

// Export singleton instance
window.uiManager = new UIManager(); 