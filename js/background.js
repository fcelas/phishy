class PhishyBackground {
    constructor() {
        this.virusTotalApiKey = '502817565555cdd55c70a2a1e6703ad0913317e524780231732da90c21713897';
        this.claudeApiKey = 'YOUR_CLAUDE_API_KEY_HERE'; // Replace with actual key
        this.init();
    }

    init() {
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
            console.error('Phishy Background Error:', error);
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
            console.error('URL Analysis Error:', error);
            return { isMalicious: false, error: error.message };
        }
    }

    async checkVirusTotal(url) {
        try {
            const apiUrl = `https://www.virustotal.com/vtapi/v2/domain/report?apikey=${this.virusTotalApiKey}&domain=${encodeURIComponent(url)}`;
            
            const response = await fetch(apiUrl);
            const data = await response.json();

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
            console.error('VirusTotal API Error:', error);
            return { isMalicious: false, error: 'API unavailable' };
        }
    }

    async getAIAnalysis(url, vtResult) {
        try {
            // Placeholder for Claude AI integration
            // This will be implemented when Claude API key is provided
            if (this.claudeApiKey === 'YOUR_CLAUDE_API_KEY_HERE') {
                return {
                    summary: `Ameaça detectada: ${vtResult.threatType}. Confiança: ${vtResult.confidence}%. Recomenda-se não acessar este site.`,
                    recommendation: 'block',
                    riskLevel: vtResult.confidence > 80 ? 'high' : vtResult.confidence > 50 ? 'medium' : 'low'
                };
            }

            const prompt = `Analyze this potential security threat:
URL: ${url}
Threat Type: ${vtResult.threatType}
Confidence: ${vtResult.confidence}%
Positives: ${vtResult.positives}/${vtResult.total}
Categories: ${vtResult.categories.join(', ')}

Provide a brief Portuguese summary for the user explaining the threat and recommendation.`;

            const response = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.claudeApiKey}`,
                    'anthropic-version': '2023-06-01'
                },
                body: JSON.stringify({
                    model: 'claude-3-sonnet-20240229',
                    max_tokens: 150,
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
                riskLevel: vtResult.confidence > 80 ? 'high' : vtResult.confidence > 50 ? 'medium' : 'low'
            };
        } catch (error) {
            console.error('AI Analysis Error:', error);
            return {
                summary: `Ameaça ${vtResult.threatType} detectada com ${vtResult.confidence}% de confiança. Recomenda-se cautela.`,
                recommendation: 'warn',
                riskLevel: 'medium'
            };
        }
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
            console.error('Error getting alert history:', error);
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
            console.error('Error getting alert details:', error);
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
                console.log('Added to whitelist:', cleanUrl);
                return true;
            }
            
            return true; // Already in whitelist
        } catch (error) {
            console.error('Error adding to whitelist:', error);
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
            console.error('Error getting whitelists:', error);
            return { pauseUrls: [], noAnalysisUrls: [] };
        }
    }

    async updatePauseUrls(urls) {
        try {
            await chrome.storage.sync.set({ pauseUrls: urls });
            console.log('Pause URLs updated:', urls);
        } catch (error) {
            console.error('Error updating pause URLs:', error);
            throw error;
        }
    }

    async updateNoAnalysisUrls(urls) {
        try {
            await chrome.storage.sync.set({ noAnalysisUrls: urls });
            console.log('No analysis URLs updated:', urls);
        } catch (error) {
            console.error('Error updating no analysis URLs:', error);
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
            console.error('Error getting settings:', error);
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
            console.log('Settings updated:', settings);
            
            // Update confidence threshold based on protection level
            const thresholds = {
                'alto': 60,
                'medio': 75,
                'baixo': 90
            };
            
            this.confidenceThreshold = thresholds[settings.protectionLevel] || 60;
        } catch (error) {
            console.error('Error updating settings:', error);
            throw error;
        }
    }
}

// Initialize background script
new PhishyBackground();