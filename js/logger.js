/**
 * Phishy Extension Logger
 * Comprehensive logging system for troubleshooting and monitoring
 */

class PhishyLogger {
    constructor() {
        this.logLevels = {
            ERROR: 0,
            WARN: 1,
            INFO: 2,
            DEBUG: 3,
            TRACE: 4
        };
        
        this.currentLevel = this.logLevels.INFO;
        this.maxLogSize = 1000; // Maximum number of log entries to keep
        this.logStorage = [];
        
        // Initialize logger
        this.init();
    }

    async init() {
        // Load log level from storage
        try {
            const result = await chrome.storage.local.get(['logLevel']);
            if (result.logLevel !== undefined) {
                this.currentLevel = result.logLevel;
            }
        } catch (error) {
            console.error('Failed to load log level:', error);
        }
        
        // Load existing logs
        await this.loadLogs();
    }

    async loadLogs() {
        try {
            const result = await chrome.storage.local.get(['phishyLogs']);
            if (result.phishyLogs) {
                this.logStorage = result.phishyLogs.slice(-this.maxLogSize);
            }
        } catch (error) {
            console.error('Failed to load logs:', error);
        }
    }

    async saveLogs() {
        try {
            // Keep only the most recent logs to avoid storage bloat
            const logsToSave = this.logStorage.slice(-this.maxLogSize);
            await chrome.storage.local.set({ phishyLogs: logsToSave });
        } catch (error) {
            console.error('Failed to save logs:', error);
        }
    }

    createLogEntry(level, message, data = null, context = '') {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level: Object.keys(this.logLevels)[level],
            message: this.sanitizeMessage(message),
            data: data ? this.sanitizeData(data) : null,
            context: this.sanitizeMessage(context),
            url: this.getCurrentUrl(),
            userAgent: navigator.userAgent.substring(0, 100) // Limit UA string
        };

        return logEntry;
    }

    sanitizeMessage(message) {
        if (typeof message !== 'string') {
            message = String(message);
        }
        // Remove any potential XSS or injection attempts
        return message.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[SCRIPT_REMOVED]')
                     .replace(/javascript:/gi, 'javascript_removed:')
                     .substring(0, 1000); // Limit message length
    }

    sanitizeData(data) {
        try {
            // Deep clone and sanitize data object
            const sanitized = JSON.parse(JSON.stringify(data));
            
            // Remove sensitive fields
            const sensitiveKeys = ['password', 'token', 'apiKey', 'secret', 'auth'];
            this.removeSensitiveKeys(sanitized, sensitiveKeys);
            
            return sanitized;
        } catch (error) {
            return { error: 'Failed to serialize data', type: typeof data };
        }
    }

    removeSensitiveKeys(obj, sensitiveKeys) {
        if (typeof obj !== 'object' || obj === null) return;
        
        for (const key in obj) {
            if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive.toLowerCase()))) {
                obj[key] = '[REDACTED]';
            } else if (typeof obj[key] === 'object') {
                this.removeSensitiveKeys(obj[key], sensitiveKeys);
            }
        }
    }

    getCurrentUrl() {
        try {
            if (typeof window !== 'undefined' && window.location) {
                return window.location.href.substring(0, 200); // Limit URL length
            }
            return 'background-script';
        } catch (error) {
            return 'unknown';
        }
    }

    shouldLog(level) {
        return level <= this.currentLevel;
    }

    async log(level, message, data = null, context = '') {
        if (!this.shouldLog(level)) return;

        const logEntry = this.createLogEntry(level, message, data, context);
        
        // Add to memory storage
        this.logStorage.push(logEntry);
        
        // Maintain storage limit
        if (this.logStorage.length > this.maxLogSize) {
            this.logStorage = this.logStorage.slice(-this.maxLogSize);
        }

        // Console output for debugging
        const levelName = Object.keys(this.logLevels)[level];
        const consoleMessage = `[PHISHY-${levelName}] ${context ? `[${context}] ` : ''}${message}`;
        
        switch (level) {
            case this.logLevels.ERROR:
                console.error(consoleMessage, data);
                break;
            case this.logLevels.WARN:
                console.warn(consoleMessage, data);
                break;
            case this.logLevels.INFO:
                console.info(consoleMessage, data);
                break;
            default:
                console.log(consoleMessage, data);
        }

        // Save to persistent storage (throttled)
        this.debouncedSave();
    }

    // Debounced save to avoid excessive storage writes
    debouncedSave = this.debounce(this.saveLogs.bind(this), 1000);

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Convenience methods
    error(message, data = null, context = '') {
        return this.log(this.logLevels.ERROR, message, data, context);
    }

    warn(message, data = null, context = '') {
        return this.log(this.logLevels.WARN, message, data, context);
    }

    info(message, data = null, context = '') {
        return this.log(this.logLevels.INFO, message, data, context);
    }

    debug(message, data = null, context = '') {
        return this.log(this.logLevels.DEBUG, message, data, context);
    }

    trace(message, data = null, context = '') {
        return this.log(this.logLevels.TRACE, message, data, context);
    }

    // Performance logging
    startTimer(label) {
        const startTime = performance.now();
        return {
            end: () => {
                const duration = performance.now() - startTime;
                this.debug(`Timer ${label} completed`, { duration: `${duration.toFixed(2)}ms` }, 'PERFORMANCE');
                return duration;
            }
        };
    }

    // Get logs for display
    async getLogs(filters = {}) {
        const { level, limit = 100, context, search } = filters;
        
        let filteredLogs = [...this.logStorage];
        
        if (level) {
            filteredLogs = filteredLogs.filter(log => log.level === level);
        }
        
        if (context) {
            filteredLogs = filteredLogs.filter(log => 
                log.context.toLowerCase().includes(context.toLowerCase())
            );
        }
        
        if (search) {
            const searchTerm = search.toLowerCase();
            filteredLogs = filteredLogs.filter(log => 
                log.message.toLowerCase().includes(searchTerm) ||
                (log.data && JSON.stringify(log.data).toLowerCase().includes(searchTerm))
            );
        }
        
        return filteredLogs.slice(-limit).reverse(); // Most recent first
    }

    // Clear logs
    async clearLogs() {
        this.logStorage = [];
        try {
            await chrome.storage.local.remove(['phishyLogs']);
            this.info('Logs cleared', null, 'LOGGER');
        } catch (error) {
            this.error('Failed to clear logs', error, 'LOGGER');
        }
    }

    // Export logs
    exportLogs(format = 'json') {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `phishy-logs-${timestamp}`;
        
        let content, mimeType;
        
        if (format === 'csv') {
            content = this.logsToCSV();
            mimeType = 'text/csv';
        } else {
            content = JSON.stringify(this.logStorage, null, 2);
            mimeType = 'application/json';
        }
        
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `${filename}.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.info(`Logs exported as ${format}`, { filename }, 'LOGGER');
    }

    logsToCSV() {
        if (this.logStorage.length === 0) return 'No logs available';
        
        const headers = ['Timestamp', 'Level', 'Context', 'Message', 'Data', 'URL'];
        const csvRows = [headers.join(',')];
        
        this.logStorage.forEach(log => {
            const row = [
                log.timestamp,
                log.level,
                log.context,
                `"${log.message.replace(/"/g, '""')}"`,
                log.data ? `"${JSON.stringify(log.data).replace(/"/g, '""')}"` : '',
                log.url
            ];
            csvRows.push(row.join(','));
        });
        
        return csvRows.join('\n');
    }

    // Set log level
    async setLogLevel(level) {
        if (typeof level === 'string') {
            level = this.logLevels[level.toUpperCase()];
        }
        
        if (level >= 0 && level <= 4) {
            this.currentLevel = level;
            try {
                await chrome.storage.local.set({ logLevel: level });
                this.info(`Log level set to ${Object.keys(this.logLevels)[level]}`, null, 'LOGGER');
            } catch (error) {
                this.error('Failed to save log level', error, 'LOGGER');
            }
        } else {
            this.warn('Invalid log level', { level }, 'LOGGER');
        }
    }

    // Get system info for debugging
    getSystemInfo() {
        return {
            extension: {
                version: chrome.runtime.getManifest()?.version || 'unknown',
                id: chrome.runtime.id
            },
            browser: {
                userAgent: navigator.userAgent,
                language: navigator.language,
                cookieEnabled: navigator.cookieEnabled,
                onLine: navigator.onLine
            },
            system: {
                platform: navigator.platform,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timestamp: new Date().toISOString()
            },
            storage: {
                logCount: this.logStorage.length,
                currentLevel: Object.keys(this.logLevels)[this.currentLevel]
            }
        };
    }
}

// Global logger instance
window.PhishyLogger = PhishyLogger;

// Initialize global logger if in extension context
if (typeof chrome !== 'undefined' && chrome.runtime) {
    window.logger = new PhishyLogger();
    
    // Export for use in other scripts
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = PhishyLogger;
    }
}