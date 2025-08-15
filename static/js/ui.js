class UIManager {
    constructor() {
        this.cacheElements();
        this.showEmptyState();
    }

    cacheElements() {
        this.profileDisplayElem = document.getElementById('profileDisplay');
        this.emptyStateElem = document.getElementById('emptyState');
    }

    async displayProfile(profile) {
        if (!profile || Object.keys(profile).length === 0) {
            this.showEmptyState("Your profile could not be found or is empty. Please generate some traffic and try again.");
            this.profileDisplayElem.classList.remove('visible');
            return;
        }

        this.hideEmptyState();
        this.profileDisplayElem.classList.add('visible');

        const tcpData = this.formatTcpData(profile);
        const httpData = this.formatHttpData(profile);
        const tlsData = await this.formatTlsData(profile);

        this.profileDisplayElem.innerHTML = `
            <div class="profile-header">
                <div class="profile-ip">${profile.id}</div>
                <div class="profile-timestamp">Last seen: ${new Date(profile.last_seen).toLocaleString()}</div>
            </div>
            <div class="profile-tabs">
                <div class="tab-navigation">
                    <button class="tab-button active" data-tab="tcp">TCP</button>
                    <button class="tab-button" data-tab="tls">TLS</button>
                    <button class="tab-button" data-tab="http">HTTP</button>
                </div>
                <div class="tab-content">
                    <div class="tab-panel active" id="tcp-panel">
                        <div class="tab-panel-title">TCP Analysis</div>
                        <div class="tab-panel-content">${tcpData}</div>
                    </div>
                    <div class="tab-panel" id="tls-panel">
                        <div class="tab-panel-title">TLS Analysis</div>
                        <div class="tab-panel-content">${tlsData}</div>
                    </div>
                    <div class="tab-panel" id="http-panel">
                        <div class="tab-panel-title">HTTP Analysis</div>
                        <div class="tab-panel-content">${httpData}</div>
                    </div>
                </div>
            </div>
        `;

        this.setupTabSwitching();
    }

    formatObject(obj) {
        return Object.entries(obj)
            .map(([key, value]) => `<strong>${this.formatKey(key)}:</strong> ${value}`)
            .join('<br>');
    }

    formatTcpData(profile) {
        const subcards = [];

        if (profile.syn) {
            subcards.push(this.formatTcpSubcard('SYN (Client)', profile.syn));
        } else {
            subcards.push(this.formatTcpSubcard('SYN (Client)', null, 'No SYN packet data found yet'));
        }

        if (profile.syn_ack) {
            subcards.push(this.formatTcpSubcard('SYN-ACK (Server)', profile.syn_ack));
        } else {
            subcards.push(this.formatTcpSubcard('SYN-ACK (Server)', null, 'No SYN-ACK packet data found yet'));
        }

        if (profile.mtu) {
            subcards.push(this.formatTcpSubcard('MTU Detection', profile.mtu));
        } else {
            subcards.push(this.formatTcpSubcard('MTU Detection', null, 'No MTU discovery data found yet'));
        }

        if (profile.uptime) {
            subcards.push(this.formatTcpSubcard('Uptime Detection', profile.uptime));
        } else {
            subcards.push(this.formatTcpSubcard('Uptime Detection', null, 'No uptime detection data found yet'));
        }

        return subcards.join('');
    }

    formatHttpData(profile) {
        const subcards = [];

        if (profile.http_request) {
            subcards.push(this.formatHttpSubcard('HTTP Request (Client)', profile.http_request));
        } else {
            subcards.push(this.formatHttpSubcard('HTTP Request (Client)', null, 'No HTTP request data found yet'));
        }

        if (profile.http_response) {
            subcards.push(this.formatHttpSubcard('HTTP Response (Server)', profile.http_response));
        } else {
            subcards.push(this.formatHttpSubcard('HTTP Response (Server)', null, 'No HTTP response data found yet'));
        }

        return subcards.join('');
    }

    async formatTlsData(profile) {
        const subcards = [];

        if (profile.tls_client) {
            subcards.push(await this.formatTlsSubcard('TLS (Client)', profile.tls_client));
        } else {
            subcards.push(this.formatTlsSubcard('TLS (Client)', null, 'No TLS client data found yet'));
        }

        return subcards.join('');
    }

    formatTcpSubcard(title, data, emptyMessage = null) {
        return `<div class="tcp-subcard">
<div class="tcp-subcard-title">${title}</div>
<div class="tcp-subcard-content">
${data ? this.formatTcpFields(data) : (emptyMessage || 'No data available')}
</div>
</div>`;
    }

    formatTcpFields(data) {
        const fields = [];
        
        if (data.source) {
            fields.push(`<div class="key-value-key">Source:</div><div class="key-value-value">${data.source.ip}:${data.source.port}</div>`);
        }
        
        if (data.destination) {
            fields.push(`<div class="key-value-key">Destination:</div><div class="key-value-value">${data.destination.ip}:${data.destination.port}</div>`);
        }
        
        if (data.signature) {
            fields.push(`<div class="key-value-key">Signature:</div><div class="key-value-value">${data.signature}</div>`);
        }
        
        if (data.os_detected) {
            fields.push(`<div class="key-value-key">OS:</div><div class="key-value-value">${data.os_detected.os} (Quality: ${data.os_detected.quality})</div>`);
        }
        
        if (data.mtu_value) {
            fields.push(`<div class="key-value-key">MTU Value:</div><div class="key-value-value">${data.mtu_value}</div>`);
        }
        
        if (data.link) {
            fields.push(`<div class="key-value-key">Link:</div><div class="key-value-value">${data.link}</div>`);
        }
        
        if (data.uptime_seconds) {
            const days = Math.floor(data.uptime_seconds / (24 * 3600));
            const hours = Math.floor((data.uptime_seconds % (24 * 3600)) / 3600);
            const minutes = Math.floor((data.uptime_seconds % 3600) / 60);
            fields.push(`<div class="key-value-key">Uptime:</div><div class="key-value-value">${days}d ${hours}h ${minutes}m</div>`);
        }
        
        if (data.details) {
            fields.push(`<div class="key-value-key">Version:</div><div class="key-value-value">${data.details.version}</div>`);
            fields.push(`<div class="key-value-key">TTL:</div><div class="key-value-value">${data.details.initial_ttl}</div>`);
            if (data.details.mss) {
                fields.push(`<div class="key-value-key">MSS:</div><div class="key-value-value">${data.details.mss}</div>`);
            }
            fields.push(`<div class="key-value-key">Window Size:</div><div class="key-value-value">${data.details.window_size}</div>`);
            if (data.details.window_scale) {
                fields.push(`<div class="key-value-key">Window Scale:</div><div class="key-value-value">${data.details.window_scale}</div>`);
            }
            if (data.details.options_layout) {
                fields.push(`<div class="key-value-key">Options:</div><div class="key-value-value">${data.details.options_layout}</div>`);
            }
            if (data.details.quirks) {
                fields.push(`<div class="key-value-key">Quirks:</div><div class="key-value-value">${data.details.quirks}</div>`);
            }
        }
        
        return `<div class="key-value-list">${fields.join('')}</div>`;
    }

    formatHttpSubcard(title, data, emptyMessage = null) {
        return `<div class="http-subcard">
<div class="http-subcard-title">${title}</div>
<div class="http-subcard-content">
${data ? this.formatHttpFields(data) : (emptyMessage || 'No data available')}
</div>
</div>`;
    }

    async formatTlsSubcard(title, data, emptyMessage = null) {
        const content = data ? await this.formatTlsClient(data) : (emptyMessage || 'No data available');
        return `<div class="tcp-subcard">
<div class="tcp-subcard-title">${title}</div>
<div class="tcp-subcard-content">
${content}
</div>
</div>`;
    }

    formatHttpFields(data) {
        const fields = [];
        
        if (data.source) {
            fields.push(`<div class="key-value-key">Source:</div><div class="key-value-value">${data.source.ip}:${data.source.port}</div>`);
        }
        
        if (data.destination) {
            fields.push(`<div class="key-value-key">Destination:</div><div class="key-value-value">${data.destination.ip}:${data.destination.port}</div>`);
        }
        
        if (data.signature) {
            fields.push(`<div class="key-value-key">Signature:</div><div class="key-value-value">${data.signature}</div>`);
        }
        
        if (data.quality !== undefined) {
            fields.push(`<div class="key-value-key">Quality:</div><div class="key-value-value">${data.quality.toFixed(2)}</div>`);
        }
        
        if (data.host) {
            fields.push(`<div class="key-value-key">Host:</div><div class="key-value-value">${data.host}</div>`);
        }
        
        if (data.user_agent) {
            fields.push(`<div class="key-value-key">User-Agent:</div><div class="key-value-value">${data.user_agent}</div>`);
        }
        
        if (data.lang) {
            fields.push(`<div class="key-value-key">Language:</div><div class="key-value-value">${data.lang}</div>`);
        }
        
        if (data.accept) {
            fields.push(`<div class="key-value-key">Accept:</div><div class="key-value-value">${data.accept}</div>`);
        }
        
        if (data.accept_language) {
            fields.push(`<div class="key-value-key">Accept-Language:</div><div class="key-value-value">${data.accept_language}</div>`);
        }
        
        if (data.accept_encoding) {
            fields.push(`<div class="key-value-key">Accept-Encoding:</div><div class="key-value-value">${data.accept_encoding}</div>`);
        }
        
        if (data.connection) {
            fields.push(`<div class="key-value-key">Connection:</div><div class="key-value-value">${data.connection}</div>`);
        }
        
        if (data.server) {
            fields.push(`<div class="key-value-key">Server:</div><div class="key-value-value">${data.server}</div>`);
        }
        
        if (data.content_type) {
            fields.push(`<div class="key-value-key">Content-Type:</div><div class="key-value-value">${data.content_type}</div>`);
        }
        
        if (data.content_length) {
            fields.push(`<div class="key-value-key">Content-Length:</div><div class="key-value-value">${data.content_length}</div>`);
        }
        
        if (data.set_cookie) {
            fields.push(`<div class="key-value-key">Set-Cookie:</div><div class="key-value-value">${data.set_cookie}</div>`);
        }
        
        if (data.cache_control) {
            fields.push(`<div class="key-value-key">Cache-Control:</div><div class="key-value-value">${data.cache_control}</div>`);
        }
        
        return `<div class="key-value-list">${fields.join('')}</div>`;
    }

    async formatTlsClient(tlsClient) {
        const sourceLabel = tlsClient.source ? `${tlsClient.source.ip}:${tlsClient.source.port}` : (tlsClient.id || 'N/A');
        const destLabel = `${tlsClient.destination.ip}:${tlsClient.destination.port}`;
        
        if (!window.tlsDataCache) {
            window.tlsDataCache = {
                cipherSuites: new Map(),
                extensions: new Map(),
                signatures: new Map(), 
                curves: new Map(),
                initialized: false
            };
        }
        
        if (!window.tlsDataCache.initialized) {
            await this.initializeTlsData();
        }
        
        const decodedCiphers = tlsClient.observed.cipher_suites.map(code => {
            const hexCode = `0x${code.toString(16).toUpperCase().padStart(4, '0')}`;
            return window.tlsDataCache.cipherSuites.get(hexCode) || 
                   `Cipher Suite ${hexCode}`;
        });
        
        const decodedExtensions = tlsClient.observed.extensions.map(code => 
            window.tlsDataCache.extensions.get(code) || `Extension ${code}`
        );
        
        const decodedSignatures = tlsClient.observed.signature_algorithms.map(code =>
            window.tlsDataCache.signatures.get(code) || 
            `Signature Algorithm 0x${code.toString(16).toUpperCase().padStart(4, '0')}`
        );
        
        const decodedCurves = tlsClient.observed.elliptic_curves.map(code =>
            window.tlsDataCache.curves.get(code) || `Named Group ${code}`
        );
        const hasTls13 = decodedCiphers.some(name => 
            name.includes('TLS_AES_') || name.includes('TLS_CHACHA20_') || 
            tlsClient.observed.cipher_suites.some(code => code >= 4865 && code <= 4868)
        );
        
        const hasModernExtensions = tlsClient.observed.extensions.includes(43) || 
                                   tlsClient.observed.extensions.includes(51) || 
                                   tlsClient.observed.extensions.includes(41);
        
        return `
            <div class="key-value-list">
                <div class="key-value-key">Source:</div>
                <div class="key-value-value">${sourceLabel}</div>
                
                <div class="key-value-key">Destination:</div>
                <div class="key-value-value">${destLabel}</div>
                
                <div class="key-value-key">JA4 Hash:</div>
                <div class="key-value-value">${tlsClient.ja4}</div>
                
                <div class="key-value-key">JA4 Raw:</div>
                <div class="key-value-value">${tlsClient.ja4_raw}</div>
                
                <div class="key-value-key">JA4 Original:</div>
                <div class="key-value-value">${tlsClient.ja4_original}</div>
                
                <div class="key-value-key">JA4 Original Raw:</div>
                <div class="key-value-value">${tlsClient.ja4_original_raw}</div>
                
                <div class="key-value-key">Version:</div>
                <div class="key-value-value">${tlsClient.observed.version}</div>
                
                <div class="key-value-key">SNI:</div>
                <div class="key-value-value">${tlsClient.observed.sni || 'None'}</div>
                
                <div class="key-value-key">ALPN:</div>
                <div class="key-value-value">${tlsClient.observed.alpn || 'None'}</div>
                
                <div class="key-value-section"><strong>Security Analysis:</strong></div>
                <div class="key-value-key">TLS 1.3 Support:</div>
                <div class="key-value-value">${hasTls13 ? '✅ Yes' : '❌ No'}</div>
                
                <div class="key-value-key">Modern Extensions:</div>
                <div class="key-value-value">${hasModernExtensions ? '✅ Yes' : '❌ No'}</div>
                
                <div class="key-value-key">Total Cipher Suites:</div>
                <div class="key-value-value">${tlsClient.observed.cipher_suites.length}</div>
                
                <div class="key-value-section"><strong>Cipher Suites:</strong></div>
                ${decodedCiphers.map(cipher => `<div class="key-value-list-item">• ${cipher}</div>`).join('')}
                
                <div class="key-value-section"><strong>Extensions:</strong></div>
                ${decodedExtensions.map(ext => `<div class="key-value-list-item">• ${ext}</div>`).join('')}
                
                <div class="key-value-section"><strong>Signature Algorithms:</strong></div>
                ${decodedSignatures.map(sig => `<div class="key-value-list-item">• ${sig}</div>`).join('')}
                
                <div class="key-value-section"><strong>Elliptic Curves:</strong></div>
                ${decodedCurves.map(curve => `<div class="key-value-list-item">• ${curve}</div>`).join('')}
            </div>
        `;
    }

    async initializeTlsData() {
        try {
            // Load all TLS data from local JSON files
            const [cipherSuites, extensions, signatures, namedGroups] = await Promise.all([
                fetch('data/tls-cipher-suites.json').then(r => r.json()),
                fetch('data/tls-extensions.json').then(r => r.json()),
                fetch('data/tls-signature-algorithms.json').then(r => r.json()),
                fetch('data/tls-named-groups.json').then(r => r.json())
            ]);
            
            // Populate the cache with loaded data
            Object.entries(cipherSuites).forEach(([code, name]) => {
                window.tlsDataCache.cipherSuites.set(code, name);
            });
            
            Object.entries(extensions).forEach(([code, name]) => {
                window.tlsDataCache.extensions.set(parseInt(code), name);
            });
            
            Object.entries(signatures).forEach(([code, name]) => {
                window.tlsDataCache.signatures.set(parseInt(code), name);
            });
            
            Object.entries(namedGroups).forEach(([code, name]) => {
                window.tlsDataCache.curves.set(parseInt(code), name);
            });
            
            console.log('TLS data loaded from local files:', {
                cipherSuites: window.tlsDataCache.cipherSuites.size,
                extensions: window.tlsDataCache.extensions.size,
                signatures: window.tlsDataCache.signatures.size,
                curves: window.tlsDataCache.curves.size
            });
            
        } catch (e) {
            console.error('Failed to load TLS data from local files:', e);
        }
        
        window.tlsDataCache.initialized = true;
    }
    

    formatKey(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    showEmptyState(message = null) {
        this.profileDisplayElem.innerHTML = '';
        this.profileDisplayElem.classList.remove('visible');
        if (message) {
            const p = this.emptyStateElem.querySelector('p');
            if (p) {
                p.textContent = message;
            }
        }
        this.emptyStateElem.style.display = 'flex';
    }

    hideEmptyState() {
        this.emptyStateElem.style.display = 'none';
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

    setupTabSwitching() {
        const tabButtons = document.querySelectorAll('.tab-button');
        const tabPanels = document.querySelectorAll('.tab-panel');

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTab = button.getAttribute('data-tab');
                
                // Remove active class from all buttons and panels
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabPanels.forEach(panel => panel.classList.remove('active'));
                
                // Add active class to clicked button and corresponding panel
                button.classList.add('active');
                const targetPanel = document.getElementById(`${targetTab}-panel`);
                if (targetPanel) {
                    targetPanel.classList.add('active');
                }
            });
        });
    }
} 