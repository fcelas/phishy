/**
 * Phishy Configuration Template
 * Copy this file to config.local.js and add your API keys for development
 * 
 * For production builds, GitHub Actions will generate config.prod.js automatically
 */

const PhishyConfig = {
    // VirusTotal API Configuration
    virustotal: {
        apiKey: 'YOUR_VIRUSTOTAL_API_KEY_HERE',
        baseUrl: 'https://www.virustotal.com/vtapi/v2',
        endpoints: {
            urlReport: '/url/report',
            urlScan: '/url/scan'
        },
        rateLimits: {
            requestsPerMinute: 4, // Public API limit
            requestsPerDay: 1000
        },
        timeout: 10000 // 10 seconds
    },

    // Claude AI API Configuration  
    claude: {
        apiKey: 'YOUR_CLAUDE_API_KEY_HERE',
        baseUrl: 'https://api.anthropic.com/v1',
        model: 'claude-3-haiku-20240307', // Fast model for real-time analysis
        maxTokens: 1000,
        temperature: 0.1, // Low temperature for consistent analysis
        timeout: 8000 // 8 seconds
    },

    // Extension Configuration
    extension: {
        // Enable/disable features based on API availability
        features: {
            virusTotalIntegration: true,
            claudeAnalysis: true,
            realtimeScanning: true,
            urlWhitelist: true,
            threatStatistics: true
        },
        
        // Default settings
        defaults: {
            protectionLevel: 'alto', // alto, medio, baixo
            showNotifications: true,
            autoBlock: true,
            logLevel: 'INFO' // ERROR, WARN, INFO, DEBUG, TRACE
        },

        // Performance settings
        performance: {
            maxConcurrentRequests: 3,
            cacheTimeout: 300000, // 5 minutes
            batchSize: 10,
            debounceMs: 1000
        }
    },

    // Development/Demo Configuration
    development: {
        // Enable demo mode when APIs are not available
        demoMode: {
            enabled: false, // Will be auto-enabled if APIs missing
            mockResponses: true,
            simulateLatency: true,
            fakeThreats: [
                'malicious-site.com',
                'phishing-example.net', 
                'suspicious-domain.org'
            ]
        },
        
        // Development logging
        debug: {
            verbose: true,
            logApiCalls: true,
            showTimings: true,
            exportLogs: true
        }
    },

    // Security Configuration
    security: {
        // Input validation settings
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
        
        // Rate limiting for security
        rateLimiting: {
            apiRequests: { max: 60, windowMs: 60000 }, // 60 per minute
            uiActions: { max: 30, windowMs: 10000 }    // 30 per 10 seconds
        },

        // Content Security Policy
        csp: {
            enforceStrict: true,
            allowInlineStyles: true, // Required for dynamic styling
            reportViolations: true
        }
    }
};

// Export configuration
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PhishyConfig;
} else {
    window.PhishyConfig = PhishyConfig;
}