class PhishyConfiguracoes {
    constructor() {
        this.settings = {
            protectionLevel: 'alto',
            autoBlock: true,
            notifications: true
        };
        this.init();
    }

    async init() {
        await this.loadSettings();
        this.renderSettings();
        this.setupEventListeners();
    }

    async loadSettings() {
        try {
            const result = await chrome.runtime.sendMessage({ action: 'getSettings' });
            if (result && result.settings) {
                this.settings = { ...this.settings, ...result.settings };
            }
        } catch (error) {
            console.error('Error loading settings:', error);
        }
    }

    renderSettings() {
        // Update protection level dropdown
        const protectionSelect = document.getElementById('protection-level');
        if (protectionSelect) {
            protectionSelect.value = this.settings.protectionLevel;
        }

        // Update toggles
        const autoBlockToggle = document.getElementById('auto-block-toggle');
        if (autoBlockToggle) {
            autoBlockToggle.checked = this.settings.autoBlock;
        }

        const notificationsToggle = document.getElementById('notifications-toggle');
        if (notificationsToggle) {
            notificationsToggle.checked = this.settings.notifications;
        }

        // Update protection level info
        this.updateProtectionInfo();
    }

    setupEventListeners() {
        // Profile button
        const profileBtn = document.getElementById('profile-btn');
        if (profileBtn) {
            profileBtn.addEventListener('click', () => {
                chrome.storage.local.set({ previousPage: 'configuracoes.html' }, () => {
                    window.location.href = 'perfil.html';
                });
            });
        }

        // About button
        const aboutBtn = document.getElementById('about-btn');
        if (aboutBtn) {
            aboutBtn.addEventListener('click', () => {
                window.open('https://phishy-s.github.io', '_blank');
            });
        }

        // Navigation tabs
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                const tabName = e.currentTarget.dataset.tab;
                if (tabName) {
                    this.navigateToPage(tabName);
                }
            });
        });

        // Protection level dropdown
        const protectionSelect = document.getElementById('protection-level');
        if (protectionSelect) {
            protectionSelect.addEventListener('change', (e) => {
                this.updateProtectionLevel(e.target.value);
            });
        }

        // Auto block toggle
        const autoBlockToggle = document.getElementById('auto-block-toggle');
        if (autoBlockToggle) {
            autoBlockToggle.addEventListener('change', (e) => {
                this.updateAutoBlock(e.target.checked);
            });
        }

        // Notifications toggle
        const notificationsToggle = document.getElementById('notifications-toggle');
        if (notificationsToggle) {
            notificationsToggle.addEventListener('change', (e) => {
                this.updateNotifications(e.target.checked);
            });
        }
    }

    async updateProtectionLevel(level) {
        try {
            this.settings.protectionLevel = level;
            
            await chrome.runtime.sendMessage({
                action: 'updateSettings',
                settings: this.settings
            });

            this.updateProtectionInfo();
            this.showMessage('Nível de proteção atualizado');
        } catch (error) {
            console.error('Error updating protection level:', error);
            this.showMessage('Erro ao atualizar configuração', 'error');
        }
    }

    async updateAutoBlock(enabled) {
        try {
            this.settings.autoBlock = enabled;
            
            await chrome.runtime.sendMessage({
                action: 'updateSettings',
                settings: this.settings
            });

            this.showMessage(`Bloqueio automático ${enabled ? 'ativado' : 'desativado'}`);
        } catch (error) {
            console.error('Error updating auto block:', error);
            this.showMessage('Erro ao atualizar configuração', 'error');
        }
    }

    async updateNotifications(enabled) {
        try {
            this.settings.notifications = enabled;
            
            await chrome.runtime.sendMessage({
                action: 'updateSettings',
                settings: this.settings
            });

            this.showMessage(`Notificações ${enabled ? 'ativadas' : 'desativadas'}`);
        } catch (error) {
            console.error('Error updating notifications:', error);
            this.showMessage('Erro ao atualizar configuração', 'error');
        }
    }

    updateProtectionInfo() {
        const levels = {
            'alto': { confidence: 60, description: 'Bloqueia ameaças com 60% ou mais de confiança' },
            'medio': { confidence: 75, description: 'Bloqueia ameaças com 75% ou mais de confiança' },
            'baixo': { confidence: 90, description: 'Bloqueia apenas ameaças com 90% ou mais de confiança' }
        };

        const currentLevel = levels[this.settings.protectionLevel];
        
        // Create or update info element
        let infoElement = document.querySelector('.protection-info');
        if (!infoElement) {
            infoElement = document.createElement('div');
            infoElement.className = 'protection-info';
            
            const dropdownContainer = document.querySelector('.dropdown-container');
            if (dropdownContainer && dropdownContainer.parentNode) {
                dropdownContainer.parentNode.insertBefore(infoElement, dropdownContainer.nextSibling);
            }
        }
        
        infoElement.textContent = currentLevel.description;
    }

    getConfidenceThreshold() {
        const thresholds = {
            'alto': 60,
            'medio': 75,
            'baixo': 90
        };
        return thresholds[this.settings.protectionLevel] || 60;
    }

    showMessage(text, type = 'success') {
        // Remove existing message
        const existingMessage = document.querySelector('.message');
        if (existingMessage) {
            existingMessage.remove();
        }

        const message = document.createElement('div');
        message.className = `message ${type}`;
        message.textContent = text;
        document.body.appendChild(message);

        setTimeout(() => {
            message.remove();
        }, 3000);
    }

    navigateToPage(page) {
        switch (page) {
            case 'dashboard':
                window.location.href = '../popup.html';
                break;
            case 'alertas':
                window.location.href = 'alertas.html';
                break;
            case 'whitelist':
                window.location.href = 'whitelist.html';
                break;
            case 'configuracoes':
                // Already on configuracoes page
                break;
            default:
                this.showNotification('Página em desenvolvimento', 'info');
        }
    }

    showNotification(message, type = 'info') {
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
        
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 3000);
    }
}

// Global functions
window.openAboutPage = function() {
    window.open('https://phishy-s.github.io', '_blank');
};

window.navigateToPage = function(page) {
    switch (page) {
        case 'dashboard':
            window.location.href = '../popup.html';
            break;
        case 'alertas':
            window.location.href = 'alertas.html';
            break;
        case 'whitelist':
            window.location.href = 'whitelist.html';
            break;
        default:
            showNotification('Página em desenvolvimento', 'info');
    }
};

window.navigateToProfile = function() {
    // Store current page for back navigation
    chrome.storage.local.set({ 
        previousPage: window.location.pathname.split('/').pop() 
    }, () => {
        window.location.href = 'perfil.html';
    });
};

function showNotification(message, type = 'info') {
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
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.phishyConfiguracoes = new PhishyConfiguracoes();
});