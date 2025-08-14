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
                    <button class="tab-button" data-tab="http">HTTP</button>
                    <button class="tab-button" data-tab="tls">TLS</button>
                </div>
                <div class="tab-content">
                    <div class="tab-panel active" id="tcp-panel">
                        <div class="tab-panel-title">TCP Analysis</div>
                        <div class="tab-panel-content">${tcpData}</div>
                    </div>
                    <div class="tab-panel" id="http-panel">
                        <div class="tab-panel-title">HTTP Analysis</div>
                        <div class="tab-panel-content">${httpData}</div>
                    </div>
                    <div class="tab-panel" id="tls-panel">
                        <div class="tab-panel-title">TLS Analysis</div>
                        <div class="tab-panel-content">${tlsData}</div>
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
        
        if (data.link) {
            fields.push(`<strong>Link:</strong> ${data.link}`);
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
            fields.push(`<strong>Source:</strong> ${data.source.ip}:${data.source.port}`);
        }
        
        if (data.destination) {
            fields.push(`<strong>Destination:</strong> ${data.destination.ip}:${data.destination.port}`);
        }
        
        if (data.signature) {
            fields.push(`<strong>Signature:</strong> ${data.signature}`);
        }
        
        if (data.quality !== undefined) {
            fields.push(`<strong>Quality:</strong> ${data.quality.toFixed(2)}`);
        }
        
        if (data.host) {
            fields.push(`<strong>Host:</strong> ${data.host}`);
        }
        
        if (data.user_agent) {
            fields.push(`<strong>User-Agent:</strong> ${data.user_agent}`);
        }
        
        if (data.lang) {
            fields.push(`<strong>Language:</strong> ${data.lang}`);
        }
        
        if (data.accept) {
            fields.push(`<strong>Accept:</strong> ${data.accept}`);
        }
        
        if (data.accept_language) {
            fields.push(`<strong>Accept-Language:</strong> ${data.accept_language}`);
        }
        
        if (data.accept_encoding) {
            fields.push(`<strong>Accept-Encoding:</strong> ${data.accept_encoding}`);
        }
        
        if (data.connection) {
            fields.push(`<strong>Connection:</strong> ${data.connection}`);
        }
        
        if (data.server) {
            fields.push(`<strong>Server:</strong> ${data.server}`);
        }
        
        if (data.content_type) {
            fields.push(`<strong>Content-Type:</strong> ${data.content_type}`);
        }
        
        if (data.content_length) {
            fields.push(`<strong>Content-Length:</strong> ${data.content_length}`);
        }
        
        if (data.set_cookie) {
            fields.push(`<strong>Set-Cookie:</strong> ${data.set_cookie}`);
        }
        
        if (data.cache_control) {
            fields.push(`<strong>Cache-Control:</strong> ${data.cache_control}`);
        }
        
        return fields.join('<br>');
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
        
        const allInfo = [
            `<strong>Source:</strong> ${sourceLabel}`,
            `<strong>Destination:</strong> ${destLabel}`,
            `<strong>JA4 Hash:</strong> ${tlsClient.ja4}`,
            `<strong>JA4 Raw:</strong> ${tlsClient.ja4_raw}`,
            `<strong>JA4 Original:</strong> ${tlsClient.ja4_original}`,
            `<strong>JA4 Original Raw:</strong> ${tlsClient.ja4_original_raw}`,
            `<strong>Version:</strong> ${tlsClient.observed.version}`,
            `<strong>SNI:</strong> ${tlsClient.observed.sni || 'None'}`,
            `<strong>ALPN:</strong> ${tlsClient.observed.alpn || 'None'}`,
            `<br><strong>Security Analysis:</strong>`,
            `&nbsp;&nbsp;TLS 1.3 Support: ${hasTls13 ? '✅ Yes' : '❌ No'}`,
            `&nbsp;&nbsp;Modern Extensions: ${hasModernExtensions ? '✅ Yes' : '❌ No'}`,
            `&nbsp;&nbsp;Total Cipher Suites: ${tlsClient.observed.cipher_suites.length}`,
            `<br><strong>Cipher Suites:</strong>`,
            ...decodedCiphers.map(cipher => `&nbsp;&nbsp;• ${cipher}`),
            `<br><strong>Extensions:</strong>`,
            ...decodedExtensions.map(ext => `&nbsp;&nbsp;• ${ext}`),
            `<br><strong>Signature Algorithms:</strong>`,
            ...decodedSignatures.map(sig => `&nbsp;&nbsp;• ${sig}`),
            `<br><strong>Elliptic Curves:</strong>`,
            ...decodedCurves.map(curve => `&nbsp;&nbsp;• ${curve}`),
        ].filter(Boolean);

        return allInfo.join('<br>');
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