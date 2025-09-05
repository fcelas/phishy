class PhishyAlertas {
    constructor() {
        this.alerts = [];
        this.stats = {};
        this.init();
    }

    async init() {
        this.setupEventListeners();
        await this.loadData();
        this.renderStats();
        this.renderAlerts();
        
        // Refresh data every 30 seconds
        setInterval(() => this.loadData(), 30000);
    }

    setupEventListeners() {
        // Profile button
        const profileBtn = document.getElementById('profile-btn');
        if (profileBtn) {
            profileBtn.addEventListener('click', () => {
                chrome.storage.local.set({ previousPage: 'alertas.html' }, () => {
                    window.location.href = 'perfil.html';
                });
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
    }

    async loadData() {
        try {
            // Get alert history from storage
            const result = await chrome.runtime.sendMessage({ action: 'getAlertHistory' });
            if (result && result.alerts) {
                // Filter alerts from last 90 days
                const ninetyDaysAgo = new Date();
                ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
                
                this.alerts = result.alerts.filter(alert => {
                    const alertDate = new Date(alert.timestamp);
                    return alertDate >= ninetyDaysAgo;
                });
            }

            // Get stats
            const statsResponse = await chrome.runtime.sendMessage({ action: 'getStats' });
            if (statsResponse && statsResponse.stats) {
                this.stats = statsResponse.stats;
            }

            this.renderStats();
            this.renderAlerts();
        } catch (error) {
            console.error('Error loading alerts data:', error);
            this.showError('Erro ao carregar dados dos alertas');
        }
    }

    renderStats() {
        // Total threats detected
        const threatsElement = document.getElementById('threats-detected');
        if (threatsElement) {
            const totalThreats = this.alerts.length;
            threatsElement.textContent = totalThreats;
        }

        // Links blocked (only blocked alerts)
        const blockedElement = document.getElementById('links-blocked');
        if (blockedElement) {
            const blockedAlerts = this.alerts.filter(alert => alert.blocked).length;
            blockedElement.textContent = blockedAlerts;
        }

        // Last alert time
        const lastAlertElement = document.getElementById('last-alert');
        if (lastAlertElement && this.alerts.length > 0) {
            const lastAlert = this.alerts[0]; // Alerts are sorted by timestamp DESC
            const lastTime = this.formatRelativeTime(new Date(lastAlert.timestamp));
            lastAlertElement.textContent = `Último Alerta: ${lastTime}`;
        } else if (lastAlertElement) {
            lastAlertElement.textContent = 'Nenhum alerta recente';
        }
    }

    renderAlerts() {
        const alertsList = document.getElementById('alerts-list');
        if (!alertsList) return;

        if (this.alerts.length === 0) {
            alertsList.innerHTML = '<div class="no-alerts">Nenhum alerta nos últimos 90 dias</div>';
            return;
        }

        alertsList.innerHTML = '';
        
        this.alerts.forEach(alert => {
            const alertElement = this.createAlertElement(alert);
            alertsList.appendChild(alertElement);
        });

        // Add event listeners to details buttons
        this.setupDetailsButtonListeners();
    }

    setupDetailsButtonListeners() {
        const detailsButtons = document.querySelectorAll('.details-btn');
        detailsButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const alertId = button.dataset.alertId;
                if (alertId) {
                    this.viewDetails(alertId);
                }
            });
        });
    }

    createAlertElement(alert) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert-item';

        const threatTypeDisplay = this.getThreatTypeDisplay(alert.threatType);
        const detectionInfo = this.getDetectionInfo(alert);
        const confidenceClass = this.getConfidenceClass(alert.confidence);
        const statusClass = alert.blocked ? 'alert-blocked' : 'alert-not-blocked';
        const statusText = alert.blocked ? 'Bloqueado' : 'Não Bloqueado';

        alertDiv.innerHTML = `
            <div class="alert-url">${alert.url}</div>
            <div class="alert-info ${statusClass}">
                ${threatTypeDisplay} • ${statusText} • ${detectionInfo}
            </div>
            <div class="alert-actions">
                <div class="confidence-info">
                    <span class="confidence-label">Confiança</span>
                    <span class="confidence-value ${confidenceClass}">${alert.confidence}%</span>
                </div>
                <button class="details-btn" data-alert-id="${alert.id}">
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                        <path d="M2.5 2.5L5 5L2.5 7.5" stroke="#F95840" stroke-width="0.6" stroke-linecap="round" stroke-linejoin="round"/>
                        <circle cx="5" cy="5" r="4" stroke="currentColor" stroke-width="0.6"/>
                    </svg>
                    <span>Detalhes</span>
                </button>
            </div>
        `;

        return alertDiv;
    }

    getThreatTypeDisplay(threatType) {
        const types = {
            'phishing': 'Phishing',
            'malware': 'Malware',
            'typosquatting': 'Typosquatting',
            'suspicious': 'Suspeito'
        };
        return types[threatType] || 'Desconhecido';
    }

    getDetectionInfo(alert) {
        const date = new Date(alert.timestamp);
        const location = alert.detectedOn || 'site desconhecido';
        const time = this.formatAlertTime(date);
        
        return `Detectado em ${location} ${time}`;
    }

    getConfidenceClass(confidence) {
        if (confidence >= 80) return 'confidence-high';
        if (confidence >= 60) return 'confidence-medium';
        return 'confidence-low';
    }

    formatAlertTime(date) {
        const now = new Date();
        const diffDays = Math.floor((now - date) / (1000 * 60 * 60 * 24));
        
        if (diffDays === 0) {
            const diffHours = Math.floor((now - date) / (1000 * 60 * 60));
            if (diffHours === 0) {
                const diffMinutes = Math.floor((now - date) / (1000 * 60));
                return `${diffMinutes} minuto${diffMinutes !== 1 ? 's' : ''} atrás`;
            }
            return `Hoje às ${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
        } else if (diffDays === 1) {
            return `Ontem às ${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
        } else if (diffDays < 7) {
            const weekdays = ['Domingo', 'Segunda-feira', 'Terça-feira', 'Quarta-feira', 'Quinta-feira', 'Sexta-feira', 'Sábado'];
            return `${weekdays[date.getDay()]} às ${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
        } else {
            return `${date.getDate().toString().padStart(2, '0')}/${(date.getMonth() + 1).toString().padStart(2, '0')}/${date.getFullYear()} às ${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
        }
    }

    formatRelativeTime(date) {
        const now = new Date();
        const diffMinutes = Math.floor((now - date) / (1000 * 60));
        
        if (diffMinutes < 1) return 'agora';
        if (diffMinutes === 1) return '1 minuto atrás';
        if (diffMinutes < 60) return `${diffMinutes} minutos atrás`;
        
        const diffHours = Math.floor(diffMinutes / 60);
        if (diffHours === 1) return '1 hora atrás';
        if (diffHours < 24) return `${diffHours} horas atrás`;
        
        const diffDays = Math.floor(diffHours / 24);
        if (diffDays === 1) return '1 dia atrás';
        return `${diffDays} dias atrás`;
    }

    navigateToPage(page) {
        switch(page) {
            case 'dashboard':
                window.location.href = '../popup.html';
                break;
            case 'alertas':
                // Already on alerts page
                break;
            case 'whitelist':
                window.location.href = 'whitelist.html';
                break;
            case 'configuracoes':
                window.location.href = 'configuracoes.html';
                break;
            default:
                this.showNotification('Página em desenvolvimento', 'info');
        }
    }

    viewDetails(alertId) {
        console.log('🔍 Viewing details for alert ID:', alertId);
        
        // Store the selected alert ID for the details page
        chrome.storage.local.set({ selectedAlertId: alertId }, () => {
            console.log('✅ Alert ID stored, navigating to details page...');
            // Navigate to details page
            window.location.href = 'detalhes-alerta.html';
        });
    }

    showError(message) {
        const alertsList = document.getElementById('alerts-list');
        if (alertsList) {
            alertsList.innerHTML = `<div class="error-message">${message}</div>`;
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

// Global navigation functions
window.navigateToPage = function(page) {
    switch(page) {
        case 'dashboard':
            window.location.href = '../popup.html';
            break;
        case 'alertas':
            // Already on alerts page
            break;
        case 'whitelist':
            window.location.href = 'whitelist.html';
            break;
        case 'configuracoes':
            window.location.href = 'configuracoes.html';
            break;
        default:
            showNotification('Página em desenvolvimento', 'info');
    }
};

window.navigateToProfile = function() {
    chrome.storage.local.set({ previousPage: 'alertas.html' }, () => {
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
    window.phishyAlertas = new PhishyAlertas();
});