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
            fields.push(`<div class="key-value-key">OS detected:</div><div class="key-value-value">${data.os_detected.os}</div>`);
            fields.push(`<div class="key-value-key">Quality matching:</div><div class="key-value-value">${data.os_detected.quality}</div>`);
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
        
        if (data.up_mod_days) {
            fields.push(`<div class="key-value-key">Wrap-around period:</div><div class="key-value-value">${data.up_mod_days} days</div>`);
        }
        
        if (data.freq) {
            fields.push(`<div class="key-value-key">Clock frequency:</div><div class="key-value-value">${data.freq.toFixed(2)} Hz</div>`);
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
        
        // Browser detection (for requests)
        if (data.browser) {
            fields.push(`<div class="key-value-key">Browser detected:</div><div class="key-value-value">${data.browser.browser}</div>`);
            fields.push(`<div class="key-value-key">Quality matching:</div><div class="key-value-value">${data.browser.quality}</div>`);
        }
        
        // Web server detection (for responses)
        if (data.web_server) {
            fields.push(`<div class="key-value-key">Web Server Detected:</div><div class="key-value-value">${data.web_server.web_server}</div>`);
            fields.push(`<div class="key-value-key">Quality matching:</div><div class="key-value-value">${data.web_server.quality}</div>`);
        }
        
        // HTTP details
        if (data.details) {
            if (data.details.host) {
                fields.push(`<div class="key-value-key">Host:</div><div class="key-value-value">${data.details.host}</div>`);
            }
            
            if (data.details.user_agent) {
                fields.push(`<div class="key-value-key">User-Agent:</div><div class="key-value-value">${data.details.user_agent}</div>`);
            }
            
            if (data.details.lang) {
                fields.push(`<div class="key-value-key">Language:</div><div class="key-value-value">${data.details.lang}</div>`);
            }
            
            if (data.details.accept) {
                fields.push(`<div class="key-value-key">Accept:</div><div class="key-value-value">${data.details.accept}</div>`);
            }
            
            if (data.details.accept_language) {
                fields.push(`<div class="key-value-key">Accept-Language:</div><div class="key-value-value">${data.details.accept_language}</div>`);
            }
            
            if (data.details.accept_encoding) {
                fields.push(`<div class="key-value-key">Accept-Encoding:</div><div class="key-value-value">${data.details.accept_encoding}</div>`);
            }
            
            if (data.details.connection) {
                fields.push(`<div class="key-value-key">Connection:</div><div class="key-value-value">${data.details.connection}</div>`);
            }
            
            if (data.details.server) {
                fields.push(`<div class="key-value-key">Server:</div><div class="key-value-value">${data.details.server}</div>`);
            }
            
            if (data.details.content_type) {
                fields.push(`<div class="key-value-key">Content-Type:</div><div class="key-value-value">${data.details.content_type}</div>`);
            }
            
            if (data.details.content_length) {
                fields.push(`<div class="key-value-key">Content-Length:</div><div class="key-value-value">${data.details.content_length}</div>`);
            }
            
            if (data.details.set_cookie) {
                fields.push(`<div class="key-value-key">Set-Cookie:</div><div class="key-value-value">${data.details.set_cookie}</div>`);
            }
            
            if (data.details.cache_control) {
                fields.push(`<div class="key-value-key">Cache-Control:</div><div class="key-value-value">${data.details.cache_control}</div>`);
            }
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
            </div>
            
            <div class="tls-sections-grid tls-sections-with-cipher">
                <div class="tls-section cipher-section">
                    <div class="key-value-section"><strong>Cipher Suites Analysis:</strong></div>
                    ${this.formatCipherSuiteTable(decodedCiphers)}
                </div>
                <div class="tls-section">
                    <div class="key-value-section"><strong>Extensions:</strong></div>
                    ${this.formatExtensionsTable(decodedExtensions)}
                </div>
                <div class="tls-section">
                    <div class="key-value-section"><strong>Signature Algorithms:</strong></div>
                    ${this.formatSignatureAlgorithmsTable(decodedSignatures)}
                </div>
                <div class="tls-section">
                    <div class="key-value-section"><strong>Elliptic Curves:</strong></div>
                    ${this.formatEllipticCurvesTable(decodedCurves)}
                </div>
            </div>
        `;
    }

    formatCipherSuiteTable(cipherSuites) {
        const parsedCiphers = cipherSuites.map(cipher => this.parseCipherSuite(cipher));
        
        let tableHtml = `
            <div class="tls-table-container">
                <table class="cipher-table compact">
                    <thead>
                        <tr>
                            <th>TLS Ver</th>
                            <th>Algorithm</th>
                            <th>Key Size</th>
                            <th>Mode</th>
                            <th>Hash</th>
                            <th>PFS</th>
                            <th>Security</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        parsedCiphers.forEach(cipher => {
            const securityLevel = this.getCipherSecurityLevel(cipher);
            const securityClass = securityLevel.toLowerCase().replace(' ', '-');
            
            tableHtml += `
                <tr class="cipher-row ${securityClass}">
                    <td>${cipher.tlsVersion}</td>
                    <td>${cipher.algorithm}</td>
                    <td>${cipher.keySize}</td>
                    <td>${cipher.mode}</td>
                    <td>${cipher.hash}</td>
                    <td>${cipher.pfs ? '✅' : '❌'}</td>
                    <td><span class="security-badge ${securityClass}">${securityLevel}</span></td>
                </tr>
            `;
        });
        
        tableHtml += `
                    </tbody>
                </table>
            </div>
        `;
        
        return tableHtml;
    }

    parseCipherSuite(cipherName) {
        const cipher = {
            original: cipherName,
            tlsVersion: 'TLS 1.2',
            algorithm: 'Unknown',
            keySize: '-',
            mode: '-',
            hash: '-',
            pfs: false
        };

        if (cipherName.startsWith('TLS_AES_') || cipherName.startsWith('TLS_CHACHA20_')) {
            cipher.tlsVersion = 'TLS 1.3';
            cipher.pfs = true;
        }

        if (cipherName.includes('AES_128')) {
            cipher.algorithm = 'AES';
            cipher.keySize = '128';
        } else if (cipherName.includes('AES_256')) {
            cipher.algorithm = 'AES';
            cipher.keySize = '256';
        } else if (cipherName.includes('CHACHA20')) {
            cipher.algorithm = 'ChaCha20';
            cipher.keySize = '256';
        } else if (cipherName.includes('3DES')) {
            cipher.algorithm = '3DES';
            cipher.keySize = '168';
        }

        if (cipherName.includes('_GCM_')) {
            cipher.mode = 'GCM';
        } else if (cipherName.includes('_CBC_')) {
            cipher.mode = 'CBC';
        } else if (cipherName.includes('POLY1305')) {
            cipher.mode = 'Poly1305';
        }

        if (cipherName.includes('SHA256')) {
            cipher.hash = 'SHA256';
        } else if (cipherName.includes('SHA384')) {
            cipher.hash = 'SHA384';
        } else if (cipherName.includes('SHA512')) {
            cipher.hash = 'SHA512';
        } else if (cipherName.includes('SHA1') || cipherName.endsWith('_SHA')) {
            cipher.hash = 'SHA1';
        }

        if (cipherName.includes('ECDHE') || cipherName.includes('DHE') || cipher.tlsVersion === 'TLS 1.3') {
            cipher.pfs = true;
        }

        return cipher;
    }

    getCipherSecurityLevel(cipher) {
        if (cipher.tlsVersion === 'TLS 1.3') {
            return 'Modern';
        }

        if (cipher.algorithm === '3DES' || cipher.hash === 'SHA1') {
            return 'Weak';
        }

        if (cipher.pfs && (cipher.mode === 'GCM' || cipher.mode === 'Poly1305') && 
            (cipher.keySize === '256' || cipher.keySize === '128')) {
            return 'Strong';
        }

        return 'Acceptable';
    }

    formatExtensionsTable(extensions) {
        const parsedExtensions = extensions.map(ext => this.parseExtension(ext));
        
        let tableHtml = `
            <div class="tls-table-container">
                <table class="tls-table compact">
                    <thead>
                        <tr>
                            <th>Extension</th>
                            <th class="hide-mobile">Category</th>
                            <th>Security</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        parsedExtensions.forEach(ext => {
            const securityClass = ext.security.toLowerCase();
            tableHtml += `
                <tr class="tls-row ${securityClass}">
                    <td>${ext.name}</td>
                    <td class="hide-mobile">${ext.category}</td>
                    <td><span class="security-badge ${securityClass}">${ext.security}</span></td>
                </tr>
            `;
        });
        
        tableHtml += `</tbody></table></div>`;
        return tableHtml;
    }

    formatSignatureAlgorithmsTable(signatures) {
        const parsedSignatures = signatures.map(sig => this.parseSignatureAlgorithm(sig));
        
        let tableHtml = `
            <div class="tls-table-container">
                <table class="tls-table compact">
                    <thead>
                        <tr>
                            <th>Algorithm</th>
                            <th class="hide-mobile">Type</th>
                            <th>Hash</th>
                            <th>Security</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        parsedSignatures.forEach(sig => {
            const securityClass = sig.security.toLowerCase();
            tableHtml += `
                <tr class="tls-row ${securityClass}">
                    <td>${sig.algorithm}</td>
                    <td class="hide-mobile">${sig.type}</td>
                    <td>${sig.hash}</td>
                    <td><span class="security-badge ${securityClass}">${sig.security}</span></td>
                </tr>
            `;
        });
        
        tableHtml += `</tbody></table></div>`;
        return tableHtml;
    }

    formatEllipticCurvesTable(curves) {
        const parsedCurves = curves.map(curve => this.parseEllipticCurve(curve));
        
        let tableHtml = `
            <div class="tls-table-container">
                <table class="tls-table compact">
                    <thead>
                        <tr>
                            <th>Curve</th>
                            <th class="hide-mobile">Type</th>
                            <th>Key Size</th>
                            <th>Security</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        parsedCurves.forEach(curve => {
            const securityClass = curve.security.toLowerCase();
            tableHtml += `
                <tr class="tls-row ${securityClass}">
                    <td>${curve.name}</td>
                    <td class="hide-mobile">${curve.type}</td>
                    <td>${curve.keySize}</td>
                    <td><span class="security-badge ${securityClass}">${curve.security}</span></td>
                </tr>
            `;
        });
        
        tableHtml += `</tbody></table></div>`;
        return tableHtml;
    }

    parseExtension(extensionName) {
        const ext = {
            name: extensionName,
            category: 'Other',
            purpose: 'General',
            security: 'Standard'
        };

        if (extensionName.includes('Server Name') || extensionName.includes('SNI')) {
            ext.category = 'Identification';
            ext.purpose = 'Host identification';
            ext.security = 'Standard';
        } else if (extensionName.includes('Key Share') || extensionName.includes('Supported Groups')) {
            ext.category = 'Cryptography';
            ext.purpose = 'Key exchange';
            ext.security = 'Strong';
        } else if (extensionName.includes('Session Ticket')) {
            ext.category = 'Performance';
            ext.purpose = 'Session resumption';
            ext.security = 'Standard';
        } else if (extensionName.includes('Signature Algorithms')) {
            ext.category = 'Cryptography';
            ext.purpose = 'Authentication';
            ext.security = 'Strong';
        } else if (extensionName.includes('Extended Master Secret')) {
            ext.category = 'Security';
            ext.purpose = 'Key derivation';
            ext.security = 'Strong';
        } else if (extensionName.includes('Renegotiation')) {
            ext.category = 'Security';
            ext.purpose = 'Secure renegotiation';
            ext.security = 'Standard';
        } else if (extensionName.includes('Supported Versions')) {
            ext.category = 'Protocol';
            ext.purpose = 'Version negotiation';
            ext.security = 'Strong';
        }

        return ext;
    }

    parseSignatureAlgorithm(signatureName) {
        const sig = {
            algorithm: signatureName,
            type: 'Unknown',
            hash: 'Unknown',
            keySize: '-',
            security: 'Standard'
        };

        if (signatureName.includes('ECDSA')) {
            sig.type = 'ECDSA';
            if (signatureName.includes('secp256r1')) {
                sig.keySize = '256';
            } else if (signatureName.includes('secp384r1')) {
                sig.keySize = '384';
            }
        } else if (signatureName.includes('RSA PSS')) {
            sig.type = 'RSA-PSS';
            sig.keySize = '2048+';
        } else if (signatureName.includes('RSA PKCS1')) {
            sig.type = 'RSA-PKCS1';
            sig.keySize = '2048+';
        }

        if (signatureName.includes('SHA256')) {
            sig.hash = 'SHA-256';
            sig.security = 'Strong';
        } else if (signatureName.includes('SHA384')) {
            sig.hash = 'SHA-384';
            sig.security = 'Strong';
        } else if (signatureName.includes('SHA512')) {
            sig.hash = 'SHA-512';
            sig.security = 'Strong';
        } else if (signatureName.includes('SHA1')) {
            sig.hash = 'SHA-1';
            sig.security = 'Weak';
        }

        return sig;
    }

    parseEllipticCurve(curveName) {
        const curve = {
            name: curveName,
            type: 'Unknown',
            keySize: '-',
            performance: 'Standard',
            security: 'Standard'
        };

        if (curveName.includes('x25519')) {
            curve.type = 'Montgomery';
            curve.keySize = '256';
            curve.performance = 'High';
            curve.security = 'Modern';
        } else if (curveName.includes('secp256r1')) {
            curve.type = 'NIST P-256';
            curve.keySize = '256';
            curve.performance = 'Standard';
            curve.security = 'Strong';
        } else if (curveName.includes('secp384r1')) {
            curve.type = 'NIST P-384';
            curve.keySize = '384';
            curve.performance = 'Standard';
            curve.security = 'Strong';
        } else if (curveName.includes('secp521r1')) {
            curve.type = 'NIST P-521';
            curve.keySize = '521';
            curve.performance = 'Low';
            curve.security = 'Strong';
        }

        return curve;
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