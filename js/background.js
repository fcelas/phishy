class PhishyBackground {
    constructor() {
        this.config = null;
        this.claudeApi = null;
        this.protectionEnabled = true;
        this.isDemoMode = false;
        this.logger = null;
        
        this.stats = {
            totalBlocked: 0,
            threatTypes: {
                phishing: 0,
                typosquatting: 0,
                malware: 0
            }
        };
        
        this.init();
    }

    async init() {
        // Initialize configuration first
        await this.initializeConfig();
        
        // Listen for messages from content script and popup
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true; // Keep message channel open for async responses
        });

        // Initialize default storage
        chrome.runtime.onInstalled.addListener(() => {
            this.initializeStorage();
        });
    }

    async initializeConfig() {
        try {
            // Import scripts for service worker
            try {
                importScripts('./logger.js', './config-manager.js', './security.js', './claude-api.js');
                
                if (typeof PhishyLogger !== 'undefined') {
                    this.logger = new PhishyLogger();
                }
                
                if (typeof PhishyConfigManager !== 'undefined') {
                    const configManager = new PhishyConfigManager();
                    await configManager.loadConfig();
                    this.config = configManager.config;
                    this.isDemoMode = configManager.isDemoModeActive();
                }
            } catch (importError) {
                console.warn('Failed to import scripts:', importError);
            }
            
            // Fallback to console logging
            if (!this.logger) {
                this.logger = console;
            }
            
            // Initialize Claude API
            if (typeof ClaudeAPI !== 'undefined') {
                this.claudeApi = new ClaudeAPI();
            }
            
            this.logger.info('Background script initialized', {
                demoMode: this.isDemoMode,
                configLoaded: !!this.config
            }, 'BACKGROUND');
            
        } catch (error) {
            this.logger.error('Failed to initialize background config', error, 'BACKGROUND');
            this.logger = console;
            this.isDemoMode = true;
        }
    }

    async initializeStorage() {
        const defaultData = {
            protectionEnabled: true,
            stats: {
                totalBlocked: 0,
                linksBlockedToday: 0,
                falsePositives: 0,
                threatTypes: {
                    phishing: 0,
                    malware: 0,
                    typosquatting: 0,
                    suspicious: 0
                }
            },
            whitelist: [],
            alertHistory: []
        };

        await chrome.storage.sync.set(defaultData);
    }

    async handleMessage(request, sender, sendResponse) {
        try {
            switch (request.action) {
                case 'analyzeUrl':
                    const analysis = await this.analyzeUrl(request.url);
                    sendResponse(analysis);
                    break;

                case 'updateStats':
                    await this.updateStats(request.type, request.domain);
                    sendResponse({ success: true });
                    break;

                case 'getStats':
                    const stats = await this.getStats();
                    sendResponse(stats);
                    break;

                case 'toggleProtection':
                    await this.toggleProtection(request.enabled);
                    sendResponse({ success: true });
                    break;

                case 'getProtectionStatus':
                    const status = await this.getProtectionStatus();
                    sendResponse(status);
                    break;

                case 'pageInfo':
                    await this.updateCurrentPage(request.url, request.fullUrl);
                    sendResponse({ success: true });
                    break;

                case 'getAlertHistory':
                    const alertHistory = await this.getAlertHistory();
                    sendResponse({ alerts: alertHistory });
                    break;

                case 'getAlertDetails':
                    const alertDetails = await this.getAlertDetails(request.alertId);
                    sendResponse({ alert: alertDetails });
                    break;

                case 'addToWhitelist':
                    const whitelistResult = await this.addToWhitelist(request.url);
                    sendResponse({ success: whitelistResult });
                    break;

                case 'getWhitelists':
                    const whitelists = await this.getWhitelists();
                    sendResponse(whitelists);
                    break;

                case 'updatePauseUrls':
                    await this.updatePauseUrls(request.urls);
                    sendResponse({ success: true });
                    break;

                case 'updateNoAnalysisUrls':
                    await this.updateNoAnalysisUrls(request.urls);
                    sendResponse({ success: true });
                    break;

                case 'getSettings':
                    const settings = await this.getSettings();
                    sendResponse({ settings });
                    break;

                case 'updateSettings':
                    await this.updateSettings(request.settings);
                    sendResponse({ success: true });
                    break;

                default:
                    sendResponse({ error: 'Unknown action' });
            }
        } catch (error) {
            this.logger.error('Phishy Background Error', error, 'BACKGROUND');
            sendResponse({ error: error.message });
        }
    }

    async analyzeUrl(url) {
        try {
            // First check whitelist
            const result = await chrome.storage.sync.get(['whitelist']);
            if (result.whitelist && result.whitelist.includes(url)) {
                return { isMalicious: false, reason: 'whitelisted' };
            }

            // Check VirusTotal
            const vtResult = await this.checkVirusTotal(url);
            
            if (vtResult.isMalicious) {
                // If VirusTotal detects threat, get AI analysis
                const aiAnalysis = await this.getAIAnalysis(url, vtResult);
                
                // Log the threat
                await this.logThreat(url, vtResult, aiAnalysis);

                return {
                    isMalicious: true,
                    threatType: vtResult.threatType,
                    confidence: vtResult.confidence,
                    aiReport: aiAnalysis,
                    source: 'virustotal'
                };
            }

            return { isMalicious: false };
        } catch (error) {
            this.logger.error('URL Analysis Error', error, 'BACKGROUND');
            return { isMalicious: false, error: error.message };
        }
    }

    async checkVirusTotal(url) {
        try {
            // Use demo mode if no config or in demo mode
            if (this.isDemoMode || !this.config?.virustotal?.apiKey || 
                this.config.virustotal.apiKey === 'DEMO_MODE' || 
                this.config.virustotal.apiKey.includes('YOUR_')) {
                return this.getDemoVirusTotalResult(url);
            }

            const baseUrl = this.config.virustotal.baseUrl || 'https://www.virustotal.com/vtapi/v2';
            const endpoint = this.config.virustotal.endpoints?.urlReport || '/url/report';
            const apiUrl = `${baseUrl}${endpoint}?apikey=${this.config.virustotal.apiKey}&resource=${encodeURIComponent(url)}`;
            
            const response = await fetch(apiUrl);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const responseText = await response.text();
            if (!responseText.trim()) {
                throw new Error('Empty response from VirusTotal API');
            }
            
            const data = JSON.parse(responseText);

            if (data.response_code === 1 && data.positives > 0) {
                const confidence = Math.min((data.positives / data.total) * 100, 100);
                
                // Determine threat type based on categories
                let threatType = 'suspicious';
                if (data.categories && data.categories.length > 0) {
                    const categories = data.categories.join(' ').toLowerCase();
                    if (categories.includes('phishing')) {
                        threatType = 'phishing';
                    } else if (categories.includes('malware')) {
                        threatType = 'malware';
                    } else if (categories.includes('typosquat')) {
                        threatType = 'typosquatting';
                    }
                }

                return {
                    isMalicious: confidence > 20, // Threshold for blocking
                    threatType,
                    confidence: Math.round(confidence),
                    positives: data.positives,
                    total: data.total,
                    categories: data.categories || []
                };
            }

            return { isMalicious: false };
        } catch (error) {
            this.logger.error('VirusTotal API Error', error, 'BACKGROUND');
            return { isMalicious: false, error: 'API unavailable' };
        }
    }

    getDemoVirusTotalResult(url) {
        // Simulate VirusTotal response for demo/testing
        const fakeThreats = this.config?.development?.demoMode?.fakeThreats || [
            'malicious-site.com',
            'phishing-example.net', 
            'suspicious-domain.org',
            'fake-bank.com',
            'evil-download.net'
        ];

        try {
            const domain = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
            const isMalicious = fakeThreats.some(threat => domain.includes(threat) || threat.includes(domain));

            this.logger.debug('Demo VirusTotal check', { url, isMalicious }, 'BACKGROUND');

            return {
                isMalicious,
                confidence: isMalicious ? 85 : 15,
                threatType: isMalicious ? 'phishing' : 'safe',
                positives: isMalicious ? 5 : 0,
                total: 70,
                categories: isMalicious ? ['phishing', 'suspicious'] : [],
                source: 'virustotal-demo'
            };
        } catch (error) {
            return { isMalicious: false, error: 'Invalid URL' };
        }
    }

    async getAIAnalysis(url, vtResult) {
        try {
            // Use demo mode if no config or in demo mode
            if (this.isDemoMode || !this.config?.claude?.apiKey || 
                this.config.claude.apiKey === 'DEMO_MODE' || 
                this.config.claude.apiKey.includes('YOUR_')) {
                return this.getDemoAIAnalysis(vtResult);
            }

            const prompt = `Analyze this potential security threat:
URL: ${url}
Threat Type: ${vtResult.threatType}
Confidence: ${vtResult.confidence}%
Positives: ${vtResult.positives}/${vtResult.total}
Categories: ${vtResult.categories.join(', ')}

Provide a brief Portuguese summary for the user explaining the threat and recommendation.`;

            const baseUrl = this.config.claude.baseUrl || 'https://api.anthropic.com/v1';
            const response = await fetch(`${baseUrl}/messages`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.config.claude.apiKey,
                    'anthropic-version': '2023-06-01'
                },
                body: JSON.stringify({
                    model: this.config.claude.model || 'claude-3-haiku-20240307',
                    max_tokens: this.config.claude.maxTokens || 150,
                    temperature: this.config.claude.temperature || 0.1,
                    messages: [{
                        role: 'user',
                        content: prompt
                    }]
                })
            });

            const aiData = await response.json();
            
            return {
                summary: aiData.content[0].text,
                recommendation: vtResult.confidence > 70 ? 'block' : 'warn',
                riskLevel: vtResult.confidence > 80 ? 'high' : vtResult.confidence > 50 ? 'medium' : 'low',
                source: 'claude-ai'
            };
        } catch (error) {
            this.logger.error('AI Analysis Error', error, 'BACKGROUND');
            return this.getDemoAIAnalysis(vtResult);
        }
    }

    getDemoAIAnalysis(vtResult) {
        // Fallback AI analysis for demo mode
        const threats = {
            phishing: 'Site de phishing detectado. Este site pode estar tentando roubar suas credenciais ou informações pessoais.',
            malware: 'Site com malware detectado. Pode conter software malicioso que danifica seu dispositivo.',
            typosquatting: 'Possível typosquatting detectado. Site similar a domínios legítimos para enganar usuários.',
            suspicious: 'Atividade suspeita detectada. Recomenda-se cautela ao acessar este site.'
        };

        return {
            summary: threats[vtResult.threatType] || `Ameaça ${vtResult.threatType} detectada com ${vtResult.confidence}% de confiança. Recomenda-se cautela.`,
            recommendation: vtResult.confidence > 70 ? 'block' : 'warn',
            riskLevel: vtResult.confidence > 80 ? 'high' : vtResult.confidence > 50 ? 'medium' : 'low',
            source: 'demo'
        };
    }

    async logThreat(url, vtResult, aiAnalysis) {
        const result = await chrome.storage.sync.get(['alertHistory']);
        const alertHistory = result.alertHistory || [];

        const alert = {
            id: Date.now(),
            url,
            threatType: vtResult.threatType,
            confidence: vtResult.confidence,
            aiSummary: aiAnalysis.summary,
            timestamp: new Date().toISOString(),
            blocked: true
        };

        alertHistory.unshift(alert);
        
        // Keep only last 100 alerts
        if (alertHistory.length > 100) {
            alertHistory.splice(100);
        }

        await chrome.storage.sync.set({ alertHistory });
        
        // Also store current page context for the alert
        const currentPageResult = await chrome.storage.sync.get(['currentPage']);
        if (currentPageResult.currentPage) {
            alert.detectedOn = currentPageResult.currentPage.url;
        }
    }

    async updateStats(type, domain) {
        const result = await chrome.storage.sync.get(['stats']);
        const stats = result.stats || {
            totalBlocked: 0,
            linksBlockedToday: 0,
            falsePositives: 0,
            threatTypes: {
                phishing: 0,
                malware: 0,
                typosquatting: 0,
                suspicious: 0
            }
        };

        if (type === 'block') {
            stats.totalBlocked++;
            stats.linksBlockedToday++;
            
            // Update current page stats
            await this.updatePageStats(domain, 'block');
        }

        await chrome.storage.sync.set({ stats });
    }

    async updatePageStats(domain, action) {
        const result = await chrome.storage.sync.get(['pageStats']);
        const pageStats = result.pageStats || {};

        if (!pageStats[domain]) {
            pageStats[domain] = { blocked: 0, visited: 0 };
        }

        if (action === 'block') {
            pageStats[domain].blocked++;
        } else if (action === 'visit') {
            pageStats[domain].visited++;
        }

        await chrome.storage.sync.set({ pageStats });
    }

    async getStats() {
        const result = await chrome.storage.sync.get(['stats', 'pageStats']);
        return {
            stats: result.stats,
            pageStats: result.pageStats
        };
    }

    async toggleProtection(enabled) {
        await chrome.storage.sync.set({ protectionEnabled: enabled });
        
        // Notify all content scripts
        const tabs = await chrome.tabs.query({});
        tabs.forEach(tab => {
            chrome.tabs.sendMessage(tab.id, {
                action: 'toggleProtection',
                enabled
            }).catch(() => {
                // Ignore errors for tabs that don't have content script
            });
        });
    }

    async getProtectionStatus() {
        const result = await chrome.storage.sync.get(['protectionEnabled']);
        return { enabled: result.protectionEnabled !== false };
    }

    async updateCurrentPage(url, fullUrl) {
        await chrome.storage.sync.set({ 
            currentPage: { url, fullUrl, timestamp: Date.now() } 
        });
        
        // Track page visit
        await this.updatePageStats(url, 'visit');
    }

    async getAlertHistory() {
        try {
            const result = await chrome.storage.sync.get(['alertHistory']);
            return result.alertHistory || [];
        } catch (error) {
            this.logger.error('Error getting alert history', error, 'BACKGROUND');
            return [];
        }
    }

    async getAlertDetails(alertId) {
        try {
            const alertHistory = await this.getAlertHistory();
            const alert = alertHistory.find(alert => alert.id.toString() === alertId.toString());
            
            if (alert) {
                // Add additional processing or analysis if needed
                return {
                    ...alert,
                    detectedOn: this.extractDomainFromContext(alert),
                    vtResults: alert.vtResults || null
                };
            }
            
            return null;
        } catch (error) {
            this.logger.error('Error getting alert details', error, 'BACKGROUND');
            return null;
        }
    }

    extractDomainFromContext(alert) {
        // Try to extract the domain where the threat was detected
        if (alert.context && alert.context.referrer) {
            try {
                return new URL(alert.context.referrer).hostname;
            } catch (e) {
                // Ignore invalid URLs
            }
        }
        
        // Fallback to current page info if available
        if (alert.detectedOn) {
            return alert.detectedOn;
        }

        return 'site desconhecido';
    }

    async addToWhitelist(url) {
        try {
            const result = await chrome.storage.sync.get(['whitelist']);
            const whitelist = result.whitelist || [];
            
            // Clean URL (remove protocol and www)
            const cleanUrl = url.replace(/^https?:\/\/(www\.)?/, '');
            
            if (!whitelist.includes(cleanUrl)) {
                whitelist.push(cleanUrl);
                await chrome.storage.sync.set({ whitelist });
                
                // Log whitelist addition
                this.logger.info('Added to whitelist', { url: cleanUrl }, 'BACKGROUND');
                return true;
            }
            
            return true; // Already in whitelist
        } catch (error) {
            this.logger.error('Error adding to whitelist', error, 'BACKGROUND');
            return false;
        }
    }

    async getWhitelists() {
        try {
            const result = await chrome.storage.sync.get(['pauseUrls', 'noAnalysisUrls']);
            return {
                pauseUrls: result.pauseUrls || [],
                noAnalysisUrls: result.noAnalysisUrls || []
            };
        } catch (error) {
            this.logger.error('Error getting whitelists', error, 'BACKGROUND');
            return { pauseUrls: [], noAnalysisUrls: [] };
        }
    }

    async updatePauseUrls(urls) {
        try {
            await chrome.storage.sync.set({ pauseUrls: urls });
            this.logger.info('Pause URLs updated', { urls }, 'BACKGROUND');
        } catch (error) {
            this.logger.error('Error updating pause URLs', error, 'BACKGROUND');
            throw error;
        }
    }

    async updateNoAnalysisUrls(urls) {
        try {
            await chrome.storage.sync.set({ noAnalysisUrls: urls });
            this.logger.info('No analysis URLs updated', { urls }, 'BACKGROUND');
        } catch (error) {
            this.logger.error('Error updating no analysis URLs', error, 'BACKGROUND');
            throw error;
        }
    }

    async getSettings() {
        try {
            const result = await chrome.storage.sync.get(['extensionSettings']);
            return result.extensionSettings || {
                protectionLevel: 'alto',
                autoBlock: true,
                notifications: true
            };
        } catch (error) {
            this.logger.error('Error getting settings', error, 'BACKGROUND');
            return {
                protectionLevel: 'alto',
                autoBlock: true,
                notifications: true
            };
        }
    }

    async updateSettings(settings) {
        try {
            await chrome.storage.sync.set({ extensionSettings: settings });
            this.logger.info('Settings updated', { settings }, 'BACKGROUND');
            
            // Update confidence threshold based on protection level
            const thresholds = {
                'alto': 60,
                'medio': 75,
                'baixo': 90
            };
            
            this.confidenceThreshold = thresholds[settings.protectionLevel] || 60;
        } catch (error) {
            this.logger.error('Error updating settings', error, 'BACKGROUND');
            throw error;
        }
    }
}

// Initialize background script
new PhishyBackground();