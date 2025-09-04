class PhishyWhitelist {
    constructor() {
        this.pauseUrls = [];
        this.noAnalysisUrls = [];
        this.init();
    }

    async init() {
        await this.loadWhitelistData();
        this.renderLists();
        this.setupEventListeners();
    }

    async loadWhitelistData() {
        try {
            const result = await chrome.runtime.sendMessage({ action: 'getWhitelists' });
            if (result) {
                this.pauseUrls = result.pauseUrls || [];
                this.noAnalysisUrls = result.noAnalysisUrls || [];
            }
        } catch (error) {
            console.error('Error loading whitelist data:', error);
        }
    }

    setupEventListeners() {
        // Profile button
        const profileBtn = document.getElementById('profile-btn');
        if (profileBtn) {
            profileBtn.addEventListener('click', () => {
                chrome.storage.local.set({ previousPage: 'whitelist.html' }, () => {
                    window.location.href = 'perfil.html';
                });
            });
        }

        // Add buttons
        const addPauseBtn = document.getElementById('add-pause-btn');
        if (addPauseBtn) {
            addPauseBtn.addEventListener('click', () => {
                this.addPauseUrl();
            });
        }

        const addNoAnalysisBtn = document.getElementById('add-no-analysis-btn');
        if (addNoAnalysisBtn) {
            addNoAnalysisBtn.addEventListener('click', () => {
                this.addNoAnalysisUrl();
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

        // Enter key listeners for inputs
        const pauseInput = document.getElementById('pause-url-input');
        const noAnalysisInput = document.getElementById('no-analysis-input');

        if (pauseInput) {
            pauseInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.addPauseUrl();
                }
            });
        }

        if (noAnalysisInput) {
            noAnalysisInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.addNoAnalysisUrl();
                }
            });
        }
    }

    renderLists() {
        this.renderPauseUrls();
        this.renderNoAnalysisUrls();
    }

    renderPauseUrls() {
        const listContainer = document.getElementById('pause-url-list');
        if (!listContainer) return;

        if (this.pauseUrls.length === 0) {
            listContainer.innerHTML = '<div class="empty-list">Nenhuma URL adicionada</div>';
            return;
        }

        listContainer.innerHTML = '';
        this.pauseUrls.forEach((url, index) => {
            const urlItem = document.createElement('div');
            urlItem.className = 'url-item';
            urlItem.innerHTML = `
                <span class="url-text">${url}</span>
                <button class="remove-btn" onclick="window.phishyWhitelist.removePauseUrl(${index})">×</button>
            `;
            listContainer.appendChild(urlItem);
        });
    }

    renderNoAnalysisUrls() {
        const listContainer = document.getElementById('no-analysis-list');
        if (!listContainer) return;

        if (this.noAnalysisUrls.length === 0) {
            listContainer.innerHTML = '<div class="empty-list">Nenhuma URL adicionada</div>';
            return;
        }

        listContainer.innerHTML = '';
        this.noAnalysisUrls.forEach((url, index) => {
            const urlItem = document.createElement('div');
            urlItem.className = 'url-item';
            urlItem.innerHTML = `
                <span class="url-text">${url}</span>
                <button class="remove-btn" onclick="window.phishyWhitelist.removeNoAnalysisUrl(${index})">×</button>
            `;
            listContainer.appendChild(urlItem);
        });
    }

    async addPauseUrl() {
        const input = document.getElementById('pause-url-input');
        const url = input.value.trim();

        // Input validation with security
        if (!url) {
            this.showMessage('Digite uma URL válida', 'error');
            if (window.logger) window.logger.warn('Empty URL input attempted', null, 'WHITELIST');
            return;
        }

        // Security validation
        if (window.security) {
            const validation = window.security.validateUrl(url);
            if (!validation.valid) {
                this.showMessage(`URL inválida: ${validation.errors[0]}`, 'error');
                if (window.logger) window.logger.warn('Invalid URL rejected', { url, errors: validation.errors }, 'WHITELIST');
                return;
            }
        }

        const cleanUrl = this.cleanUrl(url);

        if (this.pauseUrls.includes(cleanUrl)) {
            this.showMessage('URL já está na lista', 'error');
            if (window.logger) window.logger.info('Duplicate URL attempted', { url: cleanUrl }, 'WHITELIST');
            return;
        }

        // Rate limiting
        if (window.security && !window.security.uiRateLimit('addPauseUrl')) {
            this.showMessage('Muitas tentativas. Tente novamente em alguns segundos.', 'error');
            return;
        }

        try {
            this.pauseUrls.push(cleanUrl);
            
            await chrome.runtime.sendMessage({
                action: 'updatePauseUrls',
                urls: this.pauseUrls
            });

            input.value = '';
            this.renderPauseUrls();
            this.showMessage('URL adicionada com sucesso', 'success');
            
            if (window.logger) {
                window.logger.info('URL added to pause list', { url: cleanUrl }, 'WHITELIST');
            }
        } catch (error) {
            console.error('Error adding pause URL:', error);
            this.showMessage('Erro ao adicionar URL', 'error');
            
            if (window.logger) {
                window.logger.error('Failed to add pause URL', error, 'WHITELIST');
            }
            
            // Rollback on error
            const index = this.pauseUrls.indexOf(cleanUrl);
            if (index > -1) {
                this.pauseUrls.splice(index, 1);
            }
        }
    }

    async addNoAnalysisUrl() {
        const input = document.getElementById('no-analysis-input');
        const url = input.value.trim();

        if (!url) {
            this.showMessage('Digite uma URL válida', 'error');
            return;
        }

        if (this.noAnalysisUrls.includes(url)) {
            this.showMessage('URL já está na lista', 'error');
            return;
        }

        try {
            const cleanUrl = this.cleanUrl(url);
            this.noAnalysisUrls.push(cleanUrl);
            
            await chrome.runtime.sendMessage({
                action: 'updateNoAnalysisUrls',
                urls: this.noAnalysisUrls
            });

            input.value = '';
            this.renderNoAnalysisUrls();
            this.showMessage('URL adicionada com sucesso', 'success');
        } catch (error) {
            console.error('Error adding no-analysis URL:', error);
            this.showMessage('Erro ao adicionar URL', 'error');
        }
    }

    async removePauseUrl(index) {
        try {
            this.pauseUrls.splice(index, 1);
            
            await chrome.runtime.sendMessage({
                action: 'updatePauseUrls',
                urls: this.pauseUrls
            });

            this.renderPauseUrls();
            this.showMessage('URL removida com sucesso', 'success');
        } catch (error) {
            console.error('Error removing pause URL:', error);
            this.showMessage('Erro ao remover URL', 'error');
        }
    }

    async removeNoAnalysisUrl(index) {
        try {
            this.noAnalysisUrls.splice(index, 1);
            
            await chrome.runtime.sendMessage({
                action: 'updateNoAnalysisUrls',
                urls: this.noAnalysisUrls
            });

            this.renderNoAnalysisUrls();
            this.showMessage('URL removida com sucesso', 'success');
        } catch (error) {
            console.error('Error removing no-analysis URL:', error);
            this.showMessage('Erro ao remover URL', 'error');
        }
    }

    cleanUrl(url) {
        // Remove protocol and www prefix
        return url.replace(/^https?:\/\/(www\.)?/, '').replace(/\/$/, '');
    }

    showMessage(text, type) {
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
                // Already on whitelist page
                break;
            case 'configuracoes':
                window.location.href = 'configuracoes.html';
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
window.addPauseUrl = function() {
    if (window.phishyWhitelist) {
        window.phishyWhitelist.addPauseUrl();
    }
};

window.addNoAnalysisUrl = function() {
    if (window.phishyWhitelist) {
        window.phishyWhitelist.addNoAnalysisUrl();
    }
};

window.navigateToPage = function(page) {
    switch (page) {
        case 'dashboard':
            window.location.href = '../popup.html';
            break;
        case 'alertas':
            window.location.href = 'alertas.html';
            break;
        case 'configuracoes':
            window.location.href = 'configuracoes.html';
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
    window.phishyWhitelist = new PhishyWhitelist();
});