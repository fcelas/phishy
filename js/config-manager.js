/**
 * Phishy Configuration Manager
 * Handles loading and managing configuration from multiple sources
 */

class PhishyConfigManager {
    constructor() {
        this.config = null;
        this.isLoaded = false;
        this.isDemoMode = false;
        this.loadPromise = null;
        
        // Initialize logger if available
        this.logger = window.logger || console;
    }

    /**
     * Load configuration from available sources
     * Priority: config.local.js > config.prod.js > chrome.storage > demo mode
     */
    async loadConfig() {
        if (this.loadPromise) {
            return this.loadPromise;
        }

        this.loadPromise = this._doLoadConfig();
        return this.loadPromise;
    }

    async _doLoadConfig() {
        if (this.isLoaded && this.config) {
            return this.config;
        }

        this.logger.info('Loading Phishy configuration...', null, 'CONFIG');

        try {
            // 1. Try to load local development config
            let config = await this._loadFromFile('local');
            
            // 2. If not found, try production config (CI/CD generated)
            if (!config) {
                config = await this._loadFromFile('prod');
            }
            
            // 3. If no file configs, try chrome storage (user settings)
            if (!config) {
                config = await this._loadFromStorage();
            }
            
            // 4. If nothing works, use demo mode
            if (!config) {
                config = this._loadDemoConfig();
                this.isDemoMode = true;
                this.logger.warn('No API configuration found, running in demo mode', null, 'CONFIG');
            }

            // Validate and sanitize configuration
            this.config = this._validateConfig(config);
            this.isLoaded = true;

            this.logger.info('Configuration loaded successfully', {
                mode: this.isDemoMode ? 'demo' : 'production',
                features: Object.keys(this.config.extension.features).filter(f => this.config.extension.features[f])
            }, 'CONFIG');

            return this.config;

        } catch (error) {
            this.logger.error('Failed to load configuration', error, 'CONFIG');
            
            // Fallback to demo mode on any error
            this.config = this._loadDemoConfig();
            this.isDemoMode = true;
            this.isLoaded = true;
            
            return this.config;
        }
    }

    /**
     * Load configuration from JavaScript file
     */
    async _loadFromFile(type) {
        try {
            // Dynamic import of configuration file
            const configPath = `../config/config.${type}.js`;
            
            // Try to load the config file
            const script = document.createElement('script');
            script.src = configPath;
            
            return new Promise((resolve) => {
                script.onload = () => {
                    if (window.PhishyConfig) {
                        this.logger.debug(`Loaded config from config.${type}.js`, null, 'CONFIG');
                        resolve(window.PhishyConfig);
                    } else {
                        resolve(null);
                    }
                    document.head.removeChild(script);
                };
                
                script.onerror = () => {
                    this.logger.debug(`Config file config.${type}.js not found`, null, 'CONFIG');
                    document.head.removeChild(script);
                    resolve(null);
                };
                
                document.head.appendChild(script);
            });
            
        } catch (error) {
            this.logger.debug(`Failed to load config.${type}.js: ${error.message}`, null, 'CONFIG');
            return null;
        }
    }

    /**
     * Load configuration from Chrome storage
     */
    async _loadFromStorage() {
        try {
            if (typeof chrome === 'undefined' || !chrome.storage) {
                return null;
            }

            const result = await chrome.storage.local.get(['phishyConfig']);
            if (result.phishyConfig && result.phishyConfig.virustotal?.apiKey) {
                this.logger.debug('Loaded config from chrome storage', null, 'CONFIG');
                return result.phishyConfig;
            }
            
            return null;
        } catch (error) {
            this.logger.debug(`Failed to load from storage: ${error.message}`, null, 'CONFIG');
            return null;
        }
    }

    /**
     * Create demo configuration with mock data
     */
    _loadDemoConfig() {
        this.logger.info('Creating demo configuration', null, 'CONFIG');
        
        return {
            virustotal: {
                apiKey: 'DEMO_MODE',
                baseUrl: 'https://demo.virustotal.com',
                endpoints: {
                    urlReport: '/url/report',
                    urlScan: '/url/scan'
                },
                rateLimits: {
                    requestsPerMinute: 999,
                    requestsPerDay: 999999
                },
                timeout: 1000
            },
            claude: {
                apiKey: 'DEMO_MODE',
                baseUrl: 'https://demo.anthropic.com',
                model: 'claude-3-haiku-demo',
                maxTokens: 1000,
                temperature: 0.1,
                timeout: 1000
            },
            extension: {
                features: {
                    virusTotalIntegration: true,
                    claudeAnalysis: true,
                    realtimeScanning: true,
                    urlWhitelist: true,
                    threatStatistics: true
                },
                defaults: {
                    protectionLevel: 'alto',
                    showNotifications: true,
                    autoBlock: true,
                    logLevel: 'INFO'
                },
                performance: {
                    maxConcurrentRequests: 3,
                    cacheTimeout: 300000,
                    batchSize: 10,
                    debounceMs: 500 // Faster in demo
                }
            },
            development: {
                demoMode: {
                    enabled: true,
                    mockResponses: true,
                    simulateLatency: true,
                    fakeThreats: [
                        'malicious-site.com',
                        'phishing-example.net',
                        'suspicious-domain.org',
                        'fake-bank.com',
                        'evil-download.net'
                    ]
                },
                debug: {
                    verbose: true,
                    logApiCalls: true,
                    showTimings: true,
                    exportLogs: true
                }
            },
            security: {
                validation: {
                    maxUrlLength: 2048,
                    maxListSize: 1000,
                    allowedProtocols: ['http:', 'https:'],
                    blockedPatterns: [
                        /javascript:/gi,
                        /data:/gi,
                        /file:/gi,
                        /vbscript:/gi
                    ]
                },
                rateLimiting: {
                    apiRequests: { max: 60, windowMs: 60000 },
                    uiActions: { max: 30, windowMs: 10000 }
                },
                csp: {
                    enforceStrict: true,
                    allowInlineStyles: true,
                    reportViolations: true
                }
            }
        };
    }

    /**
     * Validate and sanitize configuration
     */
    _validateConfig(config) {
        if (!config || typeof config !== 'object') {
            throw new Error('Invalid configuration object');
        }

        // Ensure required sections exist
        const requiredSections = ['virustotal', 'claude', 'extension'];
        for (const section of requiredSections) {
            if (!config[section]) {
                this.logger.warn(`Missing configuration section: ${section}`, null, 'CONFIG');
                config[section] = {};
            }
        }

        // Validate API keys (unless in demo mode)
        if (!this.isDemoMode) {
            if (!config.virustotal?.apiKey || config.virustotal.apiKey.includes('YOUR_')) {
                this.logger.warn('Invalid VirusTotal API key detected', { 
                    hasKey: !!config.virustotal?.apiKey,
                    keyLength: config.virustotal?.apiKey?.length || 0 
                }, 'CONFIG');
            }
            
            if (!config.claude?.apiKey || config.claude.apiKey.includes('YOUR_')) {
                this.logger.warn('Invalid Claude API key detected', { 
                    hasKey: !!config.claude?.apiKey,
                    keyLength: config.claude?.apiKey?.length || 0 
                }, 'CONFIG');
            }
        }

        // Sanitize string values
        if (window.security) {
            const sanitizeString = (str) => window.security.sanitizeInput(str, 'text');
            
            if (config.virustotal.apiKey && typeof config.virustotal.apiKey === 'string') {
                config.virustotal.apiKey = sanitizeString(config.virustotal.apiKey);
            }
            
            if (config.claude.apiKey && typeof config.claude.apiKey === 'string') {
                config.claude.apiKey = sanitizeString(config.claude.apiKey);
            }
        }

        return config;
    }

    /**
     * Save configuration to Chrome storage
     */
    async saveConfig(config) {
        try {
            if (typeof chrome === 'undefined' || !chrome.storage) {
                throw new Error('Chrome storage not available');
            }

            const sanitizedConfig = this._validateConfig(config);
            await chrome.storage.local.set({ phishyConfig: sanitizedConfig });
            
            this.config = sanitizedConfig;
            this.isLoaded = true;
            
            this.logger.info('Configuration saved successfully', null, 'CONFIG');
            return true;
            
        } catch (error) {
            this.logger.error('Failed to save configuration', error, 'CONFIG');
            return false;
        }
    }

    /**
     * Get specific configuration value with dot notation
     */
    get(path, defaultValue = null) {
        if (!this.config) {
            this.logger.warn('Configuration not loaded, returning default value', { path, defaultValue }, 'CONFIG');
            return defaultValue;
        }

        const keys = path.split('.');
        let value = this.config;
        
        for (const key of keys) {
            if (value && typeof value === 'object' && key in value) {
                value = value[key];
            } else {
                return defaultValue;
            }
        }
        
        return value;
    }

    /**
     * Check if a feature is enabled
     */
    isFeatureEnabled(feature) {
        return this.get(`extension.features.${feature}`, false);
    }

    /**
     * Check if running in demo mode
     */
    isDemoModeActive() {
        return this.isDemoMode || this.get('development.demoMode.enabled', false);
    }

    /**
     * Get API configuration for external services
     */
    getApiConfig(service) {
        const config = this.get(service);
        if (!config) {
            this.logger.warn(`API configuration not found for service: ${service}`, null, 'CONFIG');
            return null;
        }

        return {
            ...config,
            isDemoMode: this.isDemoModeActive()
        };
    }

    /**
     * Reload configuration (useful for development)
     */
    async reloadConfig() {
        this.isLoaded = false;
        this.config = null;
        this.loadPromise = null;
        return await this.loadConfig();
    }
}

// Global configuration manager instance
window.PhishyConfigManager = PhishyConfigManager;

// Initialize global config manager if in extension context
if (typeof chrome !== 'undefined' && chrome.runtime) {
    window.configManager = new PhishyConfigManager();
    
    // Auto-load config on initialization
    window.configManager.loadConfig().catch(error => {
        console.error('Failed to auto-load configuration:', error);
    });
}