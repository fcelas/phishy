class PhishyAlertDetails {
    constructor() {
        this.currentAlert = null;
        this.init();
    }

    async init() {
        await this.loadAlertDetails();
        this.setupEventListeners();
    }

    async loadAlertDetails() {
        try {
            console.log('🔍 Loading alert details...');
            
            // Get the selected alert ID from storage
            const result = await chrome.storage.local.get(['selectedAlertId']);
            console.log('📋 Selected alert ID from storage:', result.selectedAlertId);
            
            if (!result.selectedAlertId) {
                console.error('❌ No alert ID found in storage');
                this.showError('Alerta não encontrado');
                return;
            }

            // Get the alert details from the background script
            console.log('📡 Requesting alert details from background...');
            const response = await chrome.runtime.sendMessage({
                action: 'getAlertDetails',
                alertId: result.selectedAlertId
            });
            
            console.log('📊 Alert details response:', response);

            if (response && response.alert) {
                this.currentAlert = response.alert;
                this.renderAlertDetails();
            } else {
                this.showError('Não foi possível carregar os detalhes do alerta');
            }
        } catch (error) {
            console.error('Error loading alert details:', error);
            this.showError('Erro ao carregar detalhes do alerta');
        }
    }

    renderAlertDetails() {
        if (!this.currentAlert) return;

        // Update URL
        const urlElement = document.getElementById('alert-url');
        if (urlElement) {
            urlElement.textContent = this.currentAlert.url;
        }

        // Update detection details
        const detectionElement = document.getElementById('detection-details');
        if (detectionElement) {
            const detectionInfo = this.getDetectionInfo(this.currentAlert);
            detectionElement.innerHTML = detectionInfo;
        }

        // Update threat type and confidence
        const threatTypeElement = document.getElementById('threat-type');
        const confidenceLevelElement = document.getElementById('confidence-level');
        
        if (threatTypeElement) {
            const threatTypeDisplay = this.getThreatTypeDisplay(this.currentAlert.threatType);
            threatTypeElement.textContent = `${threatTypeDisplay} Detectado`;
        }

        if (confidenceLevelElement) {
            confidenceLevelElement.textContent = `Nível de Confiança: ${this.currentAlert.confidence}%`;
        }

        // Update AI summary
        this.renderAISummary();

        // Update threat indicators
        this.renderThreatIndicators();

        // Apply confidence styling
        this.applyConfidenceClass(this.currentAlert.confidence);
    }

    renderAISummary() {
        const analysisSummary = document.querySelector('.analysis-summary .threat-info');
        if (!analysisSummary || !this.currentAlert) return;

        // Check if we already have a summary text element
        let summaryTextElement = analysisSummary.querySelector('.ai-summary-text');
        
        if (!summaryTextElement) {
            summaryTextElement = document.createElement('div');
            summaryTextElement.className = 'ai-summary-text';
            analysisSummary.appendChild(summaryTextElement);
        }

        // Get AI summary from alert data
        const aiSummary = this.currentAlert.aiSummary || 
                         this.currentAlert.aiReport?.summary || 
                         'Análise de IA não disponível para este alerta.';
        
        summaryTextElement.textContent = aiSummary;
    }

    renderThreatIndicators() {
        const indicatorsList = document.getElementById('indicators-list');
        if (!indicatorsList || !this.currentAlert) return;

        // Generate indicators based on alert data
        const indicators = this.generateThreatIndicators(this.currentAlert);
        
        indicatorsList.innerHTML = '';
        indicators.forEach(indicator => {
            const li = document.createElement('li');
            li.textContent = indicator;
            indicatorsList.appendChild(li);
        });
    }

    generateThreatIndicators(alert) {
        const indicators = [];

        // Base indicators from AI analysis
        if (alert.aiSummary && alert.aiSummary.indicators) {
            indicators.push(...alert.aiSummary.indicators);
        } else {
            // Default indicators based on threat type and confidence
            switch (alert.threatType) {
                case 'phishing':
                    indicators.push('Tentativa de roubo de credenciais detectada');
                    if (alert.confidence > 90) {
                        indicators.push('Domínio similar a serviço legítimo');
                        indicators.push('Formulário de login suspeito');
                    }
                    if (alert.confidence > 80) {
                        indicators.push('Certificado SSL não confiável');
                    }
                    break;
                    
                case 'malware':
                    indicators.push('Comportamento malicioso detectado');
                    if (alert.confidence > 85) {
                        indicators.push('Comunicação com C&C server');
                        indicators.push('Tentativa de download de payload');
                    }
                    break;
                    
                case 'typosquatting':
                    indicators.push('Domínio similar a marca conhecida');
                    if (alert.confidence > 90) {
                        indicators.push('Caracteres substituídos detectados');
                    }
                    break;
                    
                default:
                    indicators.push('Atividade suspeita identificada');
                    if (alert.confidence > 80) {
                        indicators.push('Múltiplos indicadores de ameaça');
                    }
            }

            // Add generic indicators based on confidence
            if (alert.confidence > 95) {
                indicators.push('Alta correlação com ameaças conhecidas');
            } else if (alert.confidence > 70) {
                indicators.push('Padrões suspeitos identificados');
            }

            // Add VirusTotal related indicators
            if (alert.vtResults) {
                indicators.push(`Detectado por ${alert.vtResults.positives || 0} engines de segurança`);
            }
        }

        return indicators.slice(0, 4); // Limit to 4 indicators max
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
        
        return `Detectado em ${location}<br>${time}`;
    }

    formatAlertTime(date) {
        const now = new Date();
        const diffDays = Math.floor((now - date) / (1000 * 60 * 60 * 24));
        
        if (diffDays === 0) {
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

    applyConfidenceClass(confidence) {
        const analysisSection = document.querySelector('.analysis-summary');
        if (!analysisSection) return;

        // Remove existing confidence classes
        analysisSection.classList.remove('high-confidence', 'medium-confidence', 'low-confidence');

        // Apply appropriate class
        if (confidence >= 80) {
            analysisSection.classList.add('high-confidence');
        } else if (confidence >= 60) {
            analysisSection.classList.add('medium-confidence');
        } else {
            analysisSection.classList.add('low-confidence');
        }
    }

    setupEventListeners() {
        // Back button
        const backBtn = document.getElementById('back-btn');
        if (backBtn) {
            backBtn.addEventListener('click', this.navigateBack.bind(this));
        }

        // Profile button
        const profileBtn = document.getElementById('profile-btn');
        if (profileBtn) {
            profileBtn.addEventListener('click', () => {
                chrome.storage.local.set({ previousPage: 'detalhes-alerta.html' }, () => {
                    window.location.href = 'perfil.html';
                });
            });
        }

        // Whitelist button
        const whitelistBtn = document.getElementById('whitelist-btn');
        if (whitelistBtn) {
            whitelistBtn.addEventListener('click', this.addToWhitelist.bind(this));
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

    async addToWhitelist() {
        if (!this.currentAlert) return;

        try {
            const response = await chrome.runtime.sendMessage({
                action: 'addToWhitelist',
                url: this.currentAlert.url
            });

            if (response && response.success) {
                // Update button state
                const whitelistBtn = document.getElementById('whitelist-btn');
                if (whitelistBtn) {
                    whitelistBtn.textContent = 'Adicionado à Whitelist';
                    whitelistBtn.classList.add('added');
                    whitelistBtn.disabled = true;
                }

                this.showSuccess('URL adicionada à whitelist com sucesso');
            } else {
                this.showError('Erro ao adicionar à whitelist');
            }
        } catch (error) {
            console.error('Error adding to whitelist:', error);
            this.showError('Erro ao adicionar à whitelist');
        }
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
                window.location.href = 'configuracoes.html';
                break;
            default:
                this.showNotification('Página em desenvolvimento', 'info');
        }
    }

    navigateBack() {
        window.location.href = 'alertas.html';
    }

    showError(message) {
        const container = document.querySelector('.dashboard-container');
        if (container) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-message';
            errorDiv.textContent = message;
            container.insertBefore(errorDiv, container.firstChild);

            setTimeout(() => {
                errorDiv.remove();
            }, 5000);
        }
    }

    showSuccess(message) {
        const container = document.querySelector('.dashboard-container');
        if (container) {
            const successDiv = document.createElement('div');
            successDiv.className = 'success-message';
            successDiv.textContent = message;
            container.insertBefore(successDiv, container.firstChild);

            setTimeout(() => {
                successDiv.remove();
            }, 3000);
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
window.navigateBack = function() {
    window.location.href = 'alertas.html';
};

window.navigateToPage = function(page) {
    switch (page) {
        case 'dashboard':
            window.location.href = '../popup.html';
            break;
        case 'alertas':
            window.location.href = 'alertas.html';
            break;
        default:
            showNotification('Página em desenvolvimento', 'info');
    }
};

window.navigateToProfile = function() {
    showNotification('Página de Perfil em desenvolvimento', 'info');
};

window.addToWhitelist = function() {
    if (window.phishyAlertDetails) {
        window.phishyAlertDetails.addToWhitelist();
    }
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
    window.phishyAlertDetails = new PhishyAlertDetails();
});