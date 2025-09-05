class PhishyBackground {
    constructor() {
        console.log('🔧 Phishy background script starting...');
        this.config = null;
        this.claudeApi = null;
        this.protectionEnabled = true;
        this.isDemoMode = false;
        this.logger = null;
        
        // Set up periodic rate limit reset
        this.rateLimitResetInterval = setInterval(() => {
            if (this.claudeApi && typeof this.claudeApi.resetRateLimitMode === 'function') {
                this.claudeApi.resetRateLimitMode();
            }
        }, 60000); // Check every minute
        
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

        // Add demo alerts for testing if in development
        if (this.isDemoMode) {
            defaultData.alertHistory = this.createDemoAlerts();
        }

        await chrome.storage.sync.set(defaultData);
    }

    createDemoAlerts() {
        const now = new Date();
        return [
            {
                id: Date.now() - 1000,
                url: 'malicious-site.com/phishing-page',
                threatType: 'phishing',
                confidence: 85,
                aiSummary: 'Site de phishing detectado. Este site pode estar tentando roubar suas credenciais bancárias através de uma página falsa que imita um banco conhecido.',
                timestamp: new Date(now.getTime() - 2 * 60 * 60 * 1000).toISOString(), // 2 hours ago
                blocked: true,
                detectedOn: 'reddit.com',
                aiReport: {
                    summary: 'Site de phishing detectado. Este site pode estar tentando roubar suas credenciais bancárias através de uma página falsa que imita um banco conhecido.',
                    recommendation: 'block',
                    riskLevel: 'high',
                    source: 'claude-ai'
                }
            },
            {
                id: Date.now() - 2000,
                url: 'suspicious-domain.org/download',
                threatType: 'malware',
                confidence: 92,
                aiSummary: 'Site com malware detectado. Contém software malicioso que pode danificar seu dispositivo ou roubar informações pessoais.',
                timestamp: new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString(), // 1 day ago
                blocked: true,
                detectedOn: 'twitter.com',
                aiReport: {
                    summary: 'Site com malware detectado. Contém software malicioso que pode danificar seu dispositivo ou roubar informações pessoais.',
                    recommendation: 'block',
                    riskLevel: 'high',
                    source: 'claude-ai'
                }
            },
            {
                id: Date.now() - 3000,
                url: 'fake-bank.com/secure-login',
                threatType: 'typosquatting',
                confidence: 78,
                aiSummary: 'Possível typosquatting detectado. Site similar ao domínio de um banco legítimo, provavelmente usado para enganar usuários.',
                timestamp: new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000).toISOString(), // 3 days ago
                blocked: true,
                detectedOn: 'facebook.com',
                aiReport: {
                    summary: 'Possível typosquatting detectado. Site similar ao domínio de um banco legítimo, provavelmente usado para enganar usuários.',
                    recommendation: 'block',
                    riskLevel: 'medium',
                    source: 'claude-ai'
                }
            }
        ];
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

                case 'getStatus':
                    const extensionStatus = await this.getExtensionStatus();
                    sendResponse(extensionStatus);
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
            console.log(`🔬 Background analyzing URL: ${url}`);
            
            // First check whitelist
            const result = await chrome.storage.sync.get(['whitelist']);
            if (result.whitelist && result.whitelist.includes(url)) {
                console.log(`✅ URL whitelisted: ${url}`);
                return { isMalicious: false, reason: 'whitelisted' };
            }

            // Check VirusTotal
            const vtResult = await this.checkVirusTotal(url);
            console.log(`🔍 VirusTotal result for ${url}:`, vtResult);
            
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
            // Handle quota errors specifically
            if (error.message && error.message.includes('MAX_WRITE_OPERATIONS_PER_MINUTE')) {
                this.logger.warn('API quota exceeded, using fallback analysis', error, 'BACKGROUND');
                // Try to reset rate limit mode if possible
                if (this.claudeApi && typeof this.claudeApi.resetRateLimitMode === 'function') {
                    this.claudeApi.resetRateLimitMode();
                }
                return { isMalicious: false, error: 'API quota exceeded - using fallback analysis' };
            }
            
            this.logger.error('URL Analysis Error', error, 'BACKGROUND');
            return { isMalicious: false, error: error.message };
        }
    }

    async checkVirusTotal(url) {
        try {
            console.log(`🦠 Checking VirusTotal for: ${url}`);
            console.log(`🔧 Demo mode: ${this.isDemoMode}, API key exists: ${!!this.config?.virustotal?.apiKey}`);
            
            // Use demo mode if no config or in demo mode
            if (this.isDemoMode || !this.config?.virustotal?.apiKey || 
                this.config.virustotal.apiKey === 'DEMO_MODE' || 
                this.config.virustotal.apiKey.includes('YOUR_')) {
                console.log(`🎭 Using demo mode for ${url}`);
                return this.getDemoVirusTotalResult(url);
            }

            const baseUrl = this.config.virustotal.baseUrl || 'https://www.virustotal.com/vtapi/v2';
            const endpoint = this.config.virustotal.endpoints?.urlReport || '/url/report';
            const apiUrl = `${baseUrl}${endpoint}?apikey=${this.config.virustotal.apiKey}&resource=${encodeURIComponent(url)}`;
            
            console.log(`🌐 Making VirusTotal API call to: ${baseUrl}${endpoint}`);
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
            'evil-download.net',
            'badsite.com',
            'hacksite.net',
            'phishing.example.com',
            'malware-download.org',
            'scamsite.net'
        ];

        try {
            const domain = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
            
            // Whitelist of always-safe domains for demo
            const safeDomains = [
                'example.com', 'exemplo.com', 'google.com', 'github.com', 
                'stackoverflow.com', 'mozilla.org', 'wikipedia.org',
                'microsoft.com', 'apple.com', 'amazon.com'
            ];
            
            // Always consider whitelisted domains as safe
            const isWhitelisted = safeDomains.some(safe => 
                domain === safe || domain.endsWith('.' + safe)
            );
            
            if (isWhitelisted) {
                console.log(`✅ Whitelisted domain detected: ${domain}`);
                return {
                    isMalicious: false,
                    confidence: 5,
                    threatType: 'safe',
                    positives: 0,
                    total: 70,
                    categories: [],
                    source: 'virustotal-demo'
                };
            }
            
            // Fix: Use exact matching or proper domain matching, not broad includes()
            const isMalicious = fakeThreats.some(threat => {
                // Exact domain match
                if (domain === threat || threat === domain) {
                    return true;
                }
                // Check if the domain ends with the threat (subdomain check)
                if (domain.endsWith('.' + threat) || threat.endsWith('.' + domain)) {
                    return true;
                }
                return false;
            });

            console.log(`🎭 Demo VirusTotal check for ${domain}: ${isMalicious ? 'MALICIOUS' : 'SAFE'}`);
            this.logger.debug('Demo VirusTotal check', { url, domain, isMalicious }, 'BACKGROUND');

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
        try {
            console.log(`📝 Logging threat for: ${url}`, vtResult);
            
            const result = await chrome.storage.sync.get(['alertHistory']);
            const alertHistory = result.alertHistory || [];

            const alert = {
                id: Date.now(),
                url,
                threatType: vtResult.threatType,
                confidence: vtResult.confidence,
                aiSummary: aiAnalysis?.summary || 'Análise AI não disponível',
                timestamp: new Date().toISOString(),
                blocked: true
            };

            // Also store current page context for the alert
            const currentPageResult = await chrome.storage.sync.get(['currentPage']);
            if (currentPageResult.currentPage) {
                alert.detectedOn = currentPageResult.currentPage.url;
            }

            alertHistory.unshift(alert);
            
            // Keep only last 100 alerts
            if (alertHistory.length > 100) {
                alertHistory.splice(100);
            }

            await chrome.storage.sync.set({ alertHistory });
            
            console.log(`✅ Alert logged successfully. Total alerts: ${alertHistory.length}`, alert);
            
            // Update stats
            this.updateThreatStats(vtResult.threatType);
            
        } catch (error) {
            console.error('❌ Error logging threat:', error);
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

    async updateThreatStats(threatType) {
        try {
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

            // Increment the specific threat type counter
            if (stats.threatTypes[threatType] !== undefined) {
                stats.threatTypes[threatType]++;
                await chrome.storage.sync.set({ stats });
                console.log(`📊 Updated threat stats: ${threatType} = ${stats.threatTypes[threatType]}`);
            }
        } catch (error) {
            console.error('Error updating threat stats:', error);
        }
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

    async getExtensionStatus() {
        try {
            const stats = await this.getStats();
            const alertHistory = await this.getAlertHistory();
            
            return {
                active: true,
                protectionEnabled: this.protectionEnabled,
                demoMode: this.isDemoMode,
                config: {
                    hasVirusTotal: !!this.config?.virustotal?.apiKey,
                    hasClaude: !!this.config?.claude?.apiKey,
                    virusTotalDemo: this.config?.virustotal?.apiKey === 'DEMO_MODE'
                },
                stats: {
                    totalBlocked: stats.totalBlocked,
                    totalAlerts: alertHistory.length,
                    threatTypes: stats.threatTypes
                },
                lastUpdate: new Date().toISOString()
            };
        } catch (error) {
            return { 
                active: false, 
                error: error.message,
                lastUpdate: new Date().toISOString()
            };
        }
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
            console.log(`🔍 Getting alert details for ID: ${alertId}`);
            const alertHistory = await this.getAlertHistory();
            console.log(`📋 Total alerts in history: ${alertHistory.length}`);
            
            const alert = alertHistory.find(alert => alert.id.toString() === alertId.toString());
            console.log(`📊 Found alert:`, alert ? 'Yes' : 'No');
            
            if (alert) {
                const detailedAlert = {
                    ...alert,
                    detectedOn: this.extractDomainFromContext(alert),
                    vtResults: alert.vtResults || null
                };
                console.log(`✅ Returning detailed alert:`, detailedAlert);
                return detailedAlert;
            }
            
            console.log(`❌ Alert not found for ID: ${alertId}`);
            return null;
        } catch (error) {
            console.error('❌ Error getting alert details:', error);
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
console.log('🚀 Starting Phishy background script...');
const phishyBackground = new PhishyBackground();
console.log('✅ Phishy background script initialized');