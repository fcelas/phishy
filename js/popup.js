class PhishyDashboard {
    constructor() {
        this.currentPage = null;
        this.stats = null;
        this.protectionEnabled = true;
        this.init();
    }

    async init() {
        // Load initial data
        await this.loadData();
        
        // Set up event listeners
        this.setupEventListeners();
        
        // Update UI
        this.updateUI();
        
        // Refresh data every 5 seconds
        setInterval(() => this.loadData(), 5000);
    }

    async loadData() {
        try {
            // Get current page info
            try {
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                if (tab && tab.url) {
                    try {
                        this.currentPage = {
                            url: new URL(tab.url).hostname,
                            fullUrl: tab.url
                        };
                    } catch (urlError) {
                        this.currentPage = {
                            url: 'extensão',
                            fullUrl: tab.url
                        };
                    }
                }
            } catch (tabError) {
                console.warn('Could not get current tab:', tabError);
                this.currentPage = { url: 'N/A', fullUrl: '' };
            }

            // Get stats with timeout and fallback
            try {
                const response = await this.sendMessageWithTimeout({ action: 'getStats' }, 2000);
                if (response && response.stats) {
                    this.stats = response.stats;
                    this.pageStats = response.pageStats || {};
                } else {
                    // Fallback stats
                    this.stats = { totalBlocked: 0, linksBlocked: 0, threatsToday: 0 };
                    this.pageStats = {};
                }
            } catch (statsError) {
                console.warn('Could not get stats:', statsError);
                this.stats = { totalBlocked: 0, linksBlocked: 0, threatsToday: 0 };
                this.pageStats = {};
            }

            // Get protection status with fallback
            try {
                const statusResponse = await this.sendMessageWithTimeout({ action: 'getProtectionStatus' }, 2000);
                if (statusResponse && typeof statusResponse.enabled === 'boolean') {
                    this.protectionEnabled = statusResponse.enabled;
                } else {
                    // Check from storage as fallback
                    const storageResult = await chrome.storage.sync.get(['protectionEnabled']);
                    this.protectionEnabled = storageResult.protectionEnabled !== false;
                }
            } catch (statusError) {
                console.warn('Could not get protection status:', statusError);
                this.protectionEnabled = true; // Default to enabled
            }

            this.updateUI();
        } catch (error) {
            console.error('Error loading data:', error);
            this.showError('Modo offline - funcionalidade limitada');
            // Set fallback values
            this.currentPage = { url: 'N/A', fullUrl: '' };
            this.stats = { totalBlocked: 0, linksBlocked: 0, threatsToday: 0 };
            this.protectionEnabled = true;
            this.updateUI();
        }
    }

    async sendMessageWithTimeout(message, timeout = 3000) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(new Error('Message timeout'));
            }, timeout);

            chrome.runtime.sendMessage(message, (response) => {
                clearTimeout(timer);
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                } else {
                    resolve(response);
                }
            });
        });
    }

    setupEventListeners() {
        // Protection toggle
        const toggleBtn = document.getElementById('protection-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('change', () => {
                this.toggleProtection();
            });
        }

        // Navigation tabs
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                const tabName = e.currentTarget.dataset.tab;
                if (tabName) {
                    this.handleNavigation(tabName);
                }
            });
        });

        // Profile button
        const profileBtn = document.getElementById('profile-btn');
        if (profileBtn) {
            profileBtn.addEventListener('click', () => {
                this.navigateToProfile();
            });
        }
    }

    updateUI() {
        // Update current URL
        const currentUrlElement = document.getElementById('current-url');
        if (currentUrlElement && this.currentPage) {
            currentUrlElement.textContent = this.currentPage.url || 'N/A';
        }

        // Update stats
        if (this.stats) {
            this.updateStats();
        }

        // Update protection toggle
        this.updateProtectionToggle();

        // Protection rate removed for better UX

        // Update threat types
        this.updateThreatTypes();
    }

    updateStats() {
        // Links blocked on current page
        const linksBlockedElement = document.getElementById('links-blocked');
        if (linksBlockedElement && this.currentPage && this.pageStats) {
            const pageData = this.pageStats[this.currentPage.url];
            linksBlockedElement.textContent = pageData?.blocked || 0;
        }

        // Total blocked
        const totalBlockedElement = document.getElementById('total-blocked');
        if (totalBlockedElement) {
            totalBlockedElement.textContent = this.stats.totalBlocked || 0;
        }
    }

    updateProtectionToggle() {
        const toggleCheckbox = document.getElementById('protection-toggle');
        const toggleStatus = document.getElementById('toggle-status');
        
        if (toggleCheckbox) {
            toggleCheckbox.checked = this.protectionEnabled;
        }
        
        if (toggleStatus) {
            toggleStatus.textContent = this.protectionEnabled ? 'Proteção Ativa' : 'Proteção Inativa';
        }
    }

    // Protection rate functionality removed for better UX

    updateThreatTypes() {
        if (!this.stats || !this.stats.threatTypes) return;

        const threatTypes = this.stats.threatTypes;
        const total = Object.values(threatTypes).reduce((sum, count) => sum + count, 0);
        
        if (total === 0) {
            // Show placeholder data if no threats detected yet
            this.setThreatPercentage('Phishing', '0');
            this.setThreatPercentage('Typosquatting', '0');  
            this.setThreatPercentage('Malware', '0');
            return;
        }

        // Calculate and display percentages
        const phishingPercent = Math.round((threatTypes.phishing / total) * 100);
        const typosquattingPercent = Math.round((threatTypes.typosquatting / total) * 100);
        const malwarePercent = Math.round((threatTypes.malware / total) * 100);

        this.setThreatPercentage('Phishing', phishingPercent);
        this.setThreatPercentage('Typosquatting', typosquattingPercent);
        this.setThreatPercentage('Malware', malwarePercent);
    }

    setThreatPercentage(threatName, percentage) {
        const threatItems = document.querySelectorAll('.threat-item');
        threatItems.forEach(item => {
            const nameElement = item.querySelector('.threat-name');
            if (nameElement && nameElement.textContent === threatName) {
                const percentElement = item.querySelector('.threat-percentage');
                if (percentElement) {
                    percentElement.textContent = `${percentage}%`;
                }
            }
        });
    }

    async toggleProtection() {
        try {
            const toggleCheckbox = document.getElementById('protection-toggle');
            const newState = toggleCheckbox ? toggleCheckbox.checked : !this.protectionEnabled;
            
            await chrome.runtime.sendMessage({
                action: 'toggleProtection',
                enabled: newState
            });
            
            this.protectionEnabled = newState;
            this.updateProtectionToggle();
            
            // Show feedback
            this.showNotification(
                newState ? 'Proteção ativada' : 'Proteção desativada',
                newState ? 'success' : 'warning'
            );
        } catch (error) {
            console.error('Error toggling protection:', error);
            this.showError('Erro ao alterar proteção');
        }
    }

    handleNavigation(tabName) {
        // Navigate to different pages
        switch (tabName) {
            case 'dashboard':
                // Already on dashboard
                break;
            case 'alertas':
                window.location.href = 'pages/alertas.html';
                break;
            case 'whitelist':
                window.location.href = 'pages/whitelist.html';
                break;
            case 'configuracoes':
                window.location.href = 'pages/configuracoes.html';
                break;
        }
    }

    navigateToProfile() {
        // Store current page for back navigation
        chrome.storage.local.set({ 
            previousPage: 'popup.html' 
        }, () => {
            window.location.href = 'pages/perfil.html';
        });
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 10px;
            left: 50%;
            transform: translateX(-50%);
            background: ${type === 'success' ? '#4CAF50' : type === 'warning' ? '#FF9800' : '#2196F3'};
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            font-size: 12px;
            z-index: 1000;
            animation: slideDown 0.3s ease;
        `;

        document.body.appendChild(notification);
        
        // Remove after 3 seconds
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    showError(message) {
        this.showNotification(message, 'error');
    }

    showComingSoon(message) {
        this.showNotification(message, 'info');
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.phishyDashboard = new PhishyDashboard();
});

// Global function for profile navigation (called from HTML)
window.navigateToProfile = function() {
    if (window.phishyDashboard) {
        window.phishyDashboard.navigateToProfile();
    }
};

// Add CSS for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideDown {
        from {
            transform: translateX(-50%) translateY(-20px);
            opacity: 0;
        }
        to {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
        }
    }
    
    .notification {
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        font-weight: 500;
    }
    
    .notification-error {
        background: #F44336 !important;
    }
`;
document.head.appendChild(style);