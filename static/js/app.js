// Main application controller
class AppController {
    constructor(api, ui) {
        this.api = api;
        this.ui = ui;
    }

    checkDependencies() {
        if (!this.api) {
            throw new Error("Missing required dependency: HuginnAPI");
        }
        if (!this.ui) {
            throw new Error("Missing required dependency: UIManager");
        }
    }

    initialize() {
        try {
            this.checkDependencies();
            console.log('Huginn Network Profiler initialized successfully');
            this.setupEventListeners();
        } catch (error) {
            console.error('Failed to initialize the application:', error);
            // In a real app, you might want to show this error in the UI
            const body = document.querySelector('body');
            if (body) {
                body.innerHTML = `
                    <div class="init-error">
                        <h1>Huginn Network Profiler</h1>
                        <h2>Initialization Error</h2>
                        <p>${error.message}</p>
                    </div>`;
            }
        }
    }

    setupEventListeners() {
        const findMyProfileButton = document.getElementById('findMyProfile');
        const clearProfilesButton = document.getElementById('clearProfiles');

        if (findMyProfileButton) {
            findMyProfileButton.addEventListener('click', async () => {
                this.ui.showLoading();
                try {
                    const profile = await this.api.fetchMyProfile();
                    this.ui.displayProfile(profile);
                    this.ui.showSuccess('Profile loaded successfully!');
                } catch (error) {
                    console.error('Failed to fetch my profile:', error);
                    this.ui.displayProfile(null);
                    this.ui.showError(error.message || 'Could not find your profile.');
                } finally {
                    this.ui.hideLoading();
                }
            });
        }

        if (clearProfilesButton) {
            clearProfilesButton.addEventListener('click', async () => {
                this.ui.showLoading();
                try {
                    await this.api.clearAllProfiles();
                    this.ui.clearAll();
                    this.ui.showSuccess('All profiles cleared!');
                } catch (error) {
                    console.error('Failed to clear profiles:', error);
                    this.ui.showError(error.message || 'Could not clear profiles.');
                } finally {
                    this.ui.hideLoading();
                }
            });
        }
    }
}

// Entry point: Initialize the application when the DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const api = new HuginnAPI();
    const ui = new UIManager();
    const app = new AppController(api, ui);
    app.initialize();
}); 