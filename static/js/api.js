const API_BASE_URL = 'https://api.localhost';

class HuginnAPI {
    constructor() {
        this.baseUrl = '';
        this.endpoints = {
            profiles: '/api/profiles',
            myProfile: '/api/my-profile',
            stats: '/api/stats',
            health: '/health'
        };
    }

    async request(endpoint, options = {}) {
        const url = this.baseUrl + endpoint;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        };

        const requestOptions = { ...defaultOptions, ...options };

        try {
            const response = await fetch(url, requestOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            } else {
                return await response.text();
            }
        } catch (error) {
            console.error(`API request failed for ${endpoint}:`, error);
            throw error;
        }
    }

    async getHealth() {
        return this.request(this.endpoints.health);
    }

    async getAPIInfo() {
        return this.request(this.endpoints.api);
    }

    async getProfiles(filters = {}) {
        const params = new URLSearchParams();
        
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.offset) params.append('offset', filters.offset);
        if (filters.type) params.append('type', filters.type);
        if (filters.complete !== undefined) params.append('complete', filters.complete);
        if (filters.quality_min) params.append('quality_min', filters.quality_min);
        if (filters.since) params.append('since', filters.since);

        const queryString = params.toString();
        const endpoint = queryString ? `${this.endpoints.profiles}?${queryString}` : this.endpoints.profiles;
        
        return this.request(endpoint);
    }

    async getProfile(key) {
        return this.request(`${this.endpoints.profiles}/${encodeURIComponent(key)}`);
    }

    async deleteProfile(key) {
        return this.request(`${this.endpoints.profiles}/${encodeURIComponent(key)}`, {
            method: 'DELETE'
        });
    }


    async getStats() {
        return this.request(this.endpoints.stats);
    }

    async searchProfiles(query, filters = {}) {
        const params = new URLSearchParams();
        params.append('q', query);
        
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.type) params.append('type', filters.type);
        if (filters.quality_min) params.append('quality_min', filters.quality_min);

        const endpoint = `${this.endpoints.profiles}/search?${params.toString()}`;
        return this.request(endpoint);
    }

    async batchDeleteProfiles(keys) {
        const promises = keys.map(key => this.deleteProfile(key));
        return Promise.allSettled(promises);
    }

    async getProfilesPaginated(page = 1, pageSize = 20, filters = {}) {
        const offset = (page - 1) * pageSize;
        return this.getProfiles({
            ...filters,
            limit: pageSize,
            offset: offset
        });
    }

    async getFilteredProfiles(type = 'all', complete = null, qualityMin = null) {
        const filters = {};
        
        if (type !== 'all') {
            filters.type = type;
        }
        
        if (complete !== null) {
            filters.complete = complete;
        }
        
        if (qualityMin !== null) {
            filters.quality_min = qualityMin;
        }

        return this.getProfiles(filters);
    }

    async getRecentProfiles(minutes = 60) {
        const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();
        return this.getProfiles({ since });
    }

    async exportProfiles(format = 'json') {
        const profiles = await this.getProfiles();
        
        switch (format.toLowerCase()) {
            case 'json':
                return JSON.stringify(profiles, null, 2);
            case 'csv':
                return this.convertToCSV(profiles);
            default:
                throw new Error(`Unsupported export format: ${format}`);
        }
    }

    convertToCSV(data) {
        if (!data.profiles || Object.keys(data.profiles).length === 0) {
            return 'No profiles available';
        }

        const profiles = data.profiles;
        const headers = ['IP', 'Timestamp', 'TCP_OS', 'HTTP_Browser', 'TLS_JA4', 'Quality_Score'];
        const rows = [];

        for (const [ip, profile] of Object.entries(profiles)) {
            const row = [
                ip,
                profile.timestamp || '',
                profile.tcp_analysis?.os || '',
                profile.http_analysis?.browser || '',
                profile.tls_analysis?.ja4 || '',
                profile.quality_score || 0
            ];
            rows.push(row);
        }

        return [headers, ...rows].map(row => 
            row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
        ).join('\n');
    }

    async isAvailable() {
        try {
            await this.getHealth();
            return true;
        } catch (error) {
            return false;
        }
    }

    async getStatus() {
        try {
            const [health, stats] = await Promise.all([
                this.getHealth(),
                this.getStats()
            ]);
            
            return {
                available: true,
                health: health,
                stats: stats,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            return {
                available: false,
                error: error.message,
                timestamp: new Date().toISOString()
            };
        }
    }

    async fetchMyProfile() {
        const url = `${this.baseUrl}/api/my-profile`;
        console.log(`Fetching my profile from: ${url}`);
        try {
            const response = await fetch(url);
            if (!response.ok) {

                const errorBody = await response.text();
                throw new Error(`Failed to fetch profile. Status: ${response.status}. Body: ${errorBody}`);
            }
            return await response.json();
        } catch (error) {
            console.error('Error fetching my profile:', error);
            throw error;
        }
    }
    

}

window.huginnAPI = new HuginnAPI(); 