// Main Application Controller
class HuginnApp {
    constructor() {
        this.isInitialized = false;
        this.updateInterval = null;
        this.updateFrequency = 5000; // 5 seconds
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 3;
        
        this.init();
    }

    // Initialize the application
    async init() {
        console.log('🦉 Initializing Huginn Network Profiler...');
        
        try {
            // Wait for DOM to be ready
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.start());
            } else {
                await this.start();
            }
        } catch (error) {
            console.error('Failed to initialize application:', error);
            this.handleInitializationError(error);
        }
    }

    // Start the application
    async start() {
        try {
            // Check if all required modules are available
            this.checkDependencies();
            
            // Setup WebSocket handlers
            this.setupWebSocketHandlers();
            
            // Setup periodic updates
            this.setupPeriodicUpdates();
            
            // Initial data load
            await this.loadInitialData();
            
            // WebSocket temporarily disabled for HTTP/2 testing
            // this.connectWebSocket();
            console.log('WebSocket connection disabled - using polling mode only');
            
            this.isInitialized = true;
            console.log('✅ Huginn Network Profiler initialized successfully');
            
            // Add initial activity
            window.uiManager.addActivity('Application started', 'created');
            
        } catch (error) {
            console.error('Failed to start application:', error);
            this.handleStartupError(error);
        }
    }

    // Check if all dependencies are available
    checkDependencies() {
        const required = ['wsManager', 'huginnAPI', 'uiManager'];
        const missing = required.filter(dep => !window[dep]);
        
        if (missing.length > 0) {
            throw new Error(`Missing required dependencies: ${missing.join(', ')}`);
        }
    }

    // Setup WebSocket event handlers
    setupWebSocketHandlers() {
        // Connection status handlers
        window.wsManager.onConnection((connected) => {
            console.log('WebSocket connection status:', connected);
            window.uiManager.updateConnectionStatus(connected);
            
            if (connected) {
                window.uiManager.addActivity('WebSocket connected', 'created');
                this.reconnectAttempts = 0;
            } else {
                window.uiManager.addActivity('WebSocket disconnected', 'removed');
            }
        });

        // Disconnection handler
        window.wsManager.onDisconnection(() => {
            console.log('WebSocket disconnected permanently');
            window.uiManager.addActivity('WebSocket connection lost', 'removed');
            this.handleWebSocketDisconnection();
        });

        // Message handlers
        window.wsManager.on('profile_created', (data) => {
            console.log('Profile created:', data);
            this.handleProfileCreated(data);
        });

        window.wsManager.on('profile_updated', (data) => {
            console.log('Profile updated:', data);
            this.handleProfileUpdated(data);
        });

        window.wsManager.on('profile_removed', (data) => {
            console.log('Profile removed:', data);
            this.handleProfileRemoved(data);
        });

        window.wsManager.on('stats_updated', (data) => {
            console.log('Stats updated:', data);
            this.handleStatsUpdated(data);
        });

        window.wsManager.on('error', (data) => {
            console.error('WebSocket error:', data);
            this.handleWebSocketError(data);
        });
    }

    // Setup periodic updates
    setupPeriodicUpdates() {
        // Clear existing interval
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }

        // Setup new interval
        this.updateInterval = setInterval(() => {
            this.performPeriodicUpdate();
        }, this.updateFrequency);
    }

    // Perform periodic update
    async performPeriodicUpdate() {
        try {
            // Only update if WebSocket is not connected
            if (!window.wsManager.isConnected) {
                await this.updateStats();
                await this.updateProfiles();
            }
        } catch (error) {
            console.error('Periodic update failed:', error);
        }
    }

    // Load initial data
    async loadInitialData() {
        try {
            console.log('Loading initial data...');
            
            // Check API availability
            const isAvailable = await window.huginnAPI.isAvailable();
            if (!isAvailable) {
                throw new Error('API is not available');
            }

            // Load initial stats and profiles
            await Promise.all([
                this.updateStats(),
                this.updateProfiles()
            ]);

            console.log('Initial data loaded successfully');
        } catch (error) {
            console.error('Failed to load initial data:', error);
            window.uiManager.addActivity('Failed to load initial data', 'removed');
            throw error;
        }
    }

    // Connect to WebSocket
    connectWebSocket() {
        try {
            window.uiManager.updateConnectionStatusConnecting();
            window.wsManager.connect();
        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
            window.uiManager.addActivity('Failed to connect WebSocket', 'removed');
        }
    }

    // Update statistics
    async updateStats() {
        try {
            const stats = await window.huginnAPI.getStats();
            window.uiManager.updateStats(stats);
        } catch (error) {
            console.error('Failed to update stats:', error);
        }
    }

    // Update profiles
    async updateProfiles() {
        try {
            const profiles = await window.huginnAPI.getProfiles();
            window.uiManager.updateProfiles(profiles);
        } catch (error) {
            console.error('Failed to update profiles:', error);
        }
    }

    // Handle profile created
    handleProfileCreated(data) {
        window.uiManager.addActivity(`New profile created: ${data.key}`, 'created');
        this.updateProfiles();
        this.updateStats();
    }

    // Handle profile updated
    handleProfileUpdated(data) {
        window.uiManager.addActivity(`Profile updated: ${data.key}`, 'updated');
        this.updateProfiles();
        this.updateStats();
    }

    // Handle profile removed
    handleProfileRemoved(data) {
        window.uiManager.addActivity(`Profile removed: ${data.key}`, 'removed');
        this.updateProfiles();
        this.updateStats();
    }

    // Handle stats updated
    handleStatsUpdated(data) {
        window.uiManager.updateStats(data);
    }

    // Handle WebSocket error
    handleWebSocketError(data) {
        console.error('WebSocket error received:', data);
        window.uiManager.addActivity(`WebSocket error: ${data.message || 'Unknown error'}`, 'removed');
    }

    // Handle WebSocket disconnection
    handleWebSocketDisconnection() {
        // WebSocket reconnection disabled for HTTP/2 testing
        console.log('WebSocket disconnection - staying in polling mode');
        window.uiManager.addActivity('Using polling mode only', 'updated');
        this.setupPeriodicUpdates();
    }

    // Handle initialization error
    handleInitializationError(error) {
        console.error('Initialization error:', error);
        
        // Show error message to user
        document.body.innerHTML = `
            <div style="
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                height: 100vh;
                font-family: Arial, sans-serif;
                text-align: center;
                color: #721c24;
                background: #f8d7da;
            ">
                <h1>🦉 Huginn Network Profiler</h1>
                <h2>Initialization Error</h2>
                <p>Failed to initialize the application:</p>
                <p><strong>${error.message}</strong></p>
                <button onclick="location.reload()" style="
                    margin-top: 20px;
                    padding: 10px 20px;
                    background: #dc3545;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                ">Reload Page</button>
            </div>
        `;
    }

    // Handle startup error
    handleStartupError(error) {
        console.error('Startup error:', error);
        window.uiManager?.addActivity(`Startup error: ${error.message}`, 'removed');
        window.uiManager?.showError(`Failed to start application: ${error.message}`);
    }

    // Shutdown the application
    shutdown() {
        console.log('Shutting down Huginn Network Profiler...');
        
        // Clear intervals
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
        }

        // Disconnect WebSocket
        if (window.wsManager) {
            window.wsManager.disconnect();
        }

        this.isInitialized = false;
        console.log('Application shutdown complete');
    }

    // Get application status
    getStatus() {
        return {
            initialized: this.isInitialized,
            wsConnected: window.wsManager?.isConnected || false,
            reconnectAttempts: this.reconnectAttempts,
            updateFrequency: this.updateFrequency,
            timestamp: new Date().toISOString()
        };
    }

    // Manual refresh
    async refresh() {
        try {
            console.log('Manual refresh requested');
            await this.updateStats();
            await this.updateProfiles();
            window.uiManager.addActivity('Manual refresh completed', 'updated');
        } catch (error) {
            console.error('Manual refresh failed:', error);
            window.uiManager.addActivity('Manual refresh failed', 'removed');
        }
    }

    // Export data
    async exportData(format = 'json') {
        try {
            const data = await window.huginnAPI.exportProfiles(format);
            const blob = new Blob([data], { 
                type: format === 'json' ? 'application/json' : 'text/csv' 
            });
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `huginn-profiles-${new Date().toISOString().split('T')[0]}.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            window.uiManager.addActivity(`Data exported as ${format.toUpperCase()}`, 'created');
        } catch (error) {
            console.error('Export failed:', error);
            window.uiManager.showError('Failed to export data');
        }
    }
}

// Initialize application when page loads
const huginnApp = new HuginnApp();

// Export to global scope for debugging
window.huginnApp = huginnApp;

// Handle page unload
window.addEventListener('beforeunload', () => {
    huginnApp.shutdown();
});

// Handle visibility change (tab switching)
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // Page is hidden, reduce update frequency
        huginnApp.updateFrequency = 30000; // 30 seconds
    } else {
        // Page is visible, restore normal frequency
        huginnApp.updateFrequency = 5000; // 5 seconds
    }
    huginnApp.setupPeriodicUpdates();
});

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    if (window.uiManager) {
        window.uiManager.addActivity(`Error: ${event.error.message}`, 'removed');
    }
});

// Global unhandled promise rejection handler
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    if (window.uiManager) {
        window.uiManager.addActivity(`Promise rejection: ${event.reason}`, 'removed');
    }
});

console.log('🦉 Huginn Network Profiler loaded'); 