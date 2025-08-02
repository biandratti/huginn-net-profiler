// Main Application Controller
class HuginnApp {
    constructor() {
        this.init();
    }

    // Initialize the application
    async init() {
        console.log('🦉 Initializing Huginn Network Profiler...');
        
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.start());
        } else {
            this.start();
        }
    }

    // Start the application
    start() {
        try {
            this.checkDependencies();
            console.log('✅ Huginn Network Profiler initialized successfully');
            // No automatic data loading, UI is now user-driven
        } catch (error) {
            console.error('Failed to start application:', error);
            this.handleInitializationError(error);
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

    // Shutdown logic (simplified)
    shutdown() {
        console.log('Shutting down Huginn Network Profiler...');
        console.log('Application shutdown complete');
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