// Main Application Controller
class HuginnApp {
    constructor() {
        this.isInitialized = false;
        this.updateInterval = null;
        this.updateFrequency = 5000; // 5 seconds
        
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
            
            // Setup periodic updates
            this.setupPeriodicUpdates();
            
            // Initial data load
            await this.loadInitialData();
            
            this.isInitialized = true;
            console.log('✅ Huginn Network Profiler initialized successfully');
            
        } catch (error) {
            console.error('Failed to start application:', error);
            this.handleStartupError(error);
        }
    }

    // Check if all dependencies are available
    checkDependencies() {
        const required = ['huginnAPI', 'uiManager'];
        const missing = required.filter(dep => !window[dep]);
        
        if (missing.length > 0) {
            throw new Error(`Missing required dependencies: ${missing.join(', ')}`);
        }
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
            await this.updateStats();
            await this.updateProfiles();
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
            window.uiManager.showError('Failed to load initial data');
            throw error;
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
                <h1>Huginn Network Profiler</h1>
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

        this.isInitialized = false;
        console.log('Application shutdown complete');
    }

    // Manual refresh
    async refresh() {
        try {
            console.log('Manual refresh requested');
            await this.updateStats();
            await this.updateProfiles();
        } catch (error) {
            console.error('Manual refresh failed:', error);
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

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
});

// Global unhandled promise rejection handler
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
});

console.log('🦉 Huginn Network Profiler loaded'); 