// API Client for Huginn Network Profiler
class HuginnAPI {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
        this.endpoints = {
            health: '/health',
            api: '/api',
            profiles: '/api/profiles',
            stats: '/api/stats',
            search: '/api/search',
            myProfile: '/api/my-profile'
        };
    }

    // Generic HTTP request method
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

    // Health check
    async getHealth() {
        return this.request(this.endpoints.health);
    }

    // Get API information
    async getAPIInfo() {
        return this.request(this.endpoints.api);
    }

    // Get all profiles
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

    // Get specific profile
    async getProfile(key) {
        return this.request(`${this.endpoints.profiles}/${encodeURIComponent(key)}`);
    }

    // Delete specific profile
    async deleteProfile(key) {
        return this.request(`${this.endpoints.profiles}/${encodeURIComponent(key)}`, {
            method: 'DELETE'
        });
    }

    // Clear all profiles
    async clearProfiles() {
        return this.request(this.endpoints.profiles, {
            method: 'DELETE'
        });
    }

    // Get statistics
    async getStats() {
        return this.request(this.endpoints.stats);
    }

    // Search profiles
    async searchProfiles(query, filters = {}) {
        const params = new URLSearchParams();
        params.append('q', query);
        
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.type) params.append('type', filters.type);
        if (filters.quality_min) params.append('quality_min', filters.quality_min);

        const endpoint = `${this.endpoints.search}?${params.toString()}`;
        return this.request(endpoint);
    }

    // Batch operations
    async batchDeleteProfiles(keys) {
        const promises = keys.map(key => this.deleteProfile(key));
        return Promise.allSettled(promises);
    }

    // Get profiles with pagination
    async getProfilesPaginated(page = 1, pageSize = 20, filters = {}) {
        const offset = (page - 1) * pageSize;
        return this.getProfiles({
            ...filters,
            limit: pageSize,
            offset: offset
        });
    }

    // Get filtered profiles
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

    // Get recent profiles
    async getRecentProfiles(minutes = 60) {
        const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();
        return this.getProfiles({ since });
    }

    // Export profiles
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

    // Convert profiles to CSV format
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

    // Check if API is available
    async isAvailable() {
        try {
            await this.getHealth();
            return true;
        } catch (error) {
            return false;
        }
    }

    // Get API status
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

    // Fetches the network profile for the current user.
    // @returns {Promise<object>} A promise that resolves to the user's network profile.
    async fetchMyProfile() {
        try {
            const response = await fetch(`${this.baseUrl}${this.endpoints.myProfile}`);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Failed to fetch profile' }));
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('Error fetching my profile:', error);
            throw error;
        }
    }
}

// Export singleton instance
window.huginnAPI = new HuginnAPI(); 