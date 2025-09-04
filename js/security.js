/**
 * Phishy Extension Security Module
 * Input validation, sanitization, and security utilities
 */

class PhishySecurity {
    constructor() {
        this.urlPattern = /^https?:\/\/([\w-]+\.)+[\w-]+(\/[\w\-._~!$&'()*+,;=:@]*)*\/?(\?[;&\w\-._~!$'()*+,;=:@]*)?$/i;
        this.domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        this.maxInputLength = 2048;
        this.maxListSize = 1000;
        
        // Initialize security measures
        this.init();
    }

    init() {
        // Log security module initialization
        if (window.logger) {
            window.logger.info('Security module initialized', null, 'SECURITY');
        }
    }

    /**
     * URL Validation and Sanitization
     */
    validateUrl(url) {
        const errors = [];
        
        if (!url || typeof url !== 'string') {
            errors.push('URL must be a non-empty string');
            return { valid: false, errors, sanitized: '' };
        }

        if (url.length > this.maxInputLength) {
            errors.push(`URL exceeds maximum length of ${this.maxInputLength} characters`);
            return { valid: false, errors, sanitized: url.substring(0, this.maxInputLength) };
        }

        // Sanitize URL
        let sanitized = this.sanitizeUrl(url);
        
        // Validate sanitized URL
        if (!this.urlPattern.test(sanitized) && !this.domainPattern.test(sanitized)) {
            errors.push('Invalid URL or domain format');
        }

        // Check for malicious patterns
        const maliciousPatterns = this.checkMaliciousPatterns(sanitized);
        if (maliciousPatterns.length > 0) {
            errors.push('URL contains potentially malicious patterns');
            errors.push(...maliciousPatterns);
        }

        return {
            valid: errors.length === 0,
            errors,
            sanitized
        };
    }

    sanitizeUrl(url) {
        if (typeof url !== 'string') return '';
        
        // Remove dangerous characters and encode
        let sanitized = url.trim()
            .replace(/[\x00-\x1F\x7F]/g, '') // Remove control characters
            .replace(/[<>'"]/g, '') // Remove HTML-dangerous characters
            .replace(/javascript:/gi, '') // Remove javascript protocol
            .replace(/data:/gi, '') // Remove data protocol
            .replace(/file:/gi, '') // Remove file protocol
            .replace(/vbscript:/gi, '') // Remove vbscript protocol
            .replace(/mailto:/gi, ''); // Remove mailto protocol

        // Normalize protocol
        if (sanitized && !sanitized.match(/^https?:\/\//i) && sanitized.includes('.')) {
            // If it looks like a domain, don't add protocol
            if (this.domainPattern.test(sanitized)) {
                return sanitized;
            }
            // Otherwise add https
            sanitized = 'https://' + sanitized;
        }

        return sanitized;
    }

    checkMaliciousPatterns(url) {
        const issues = [];
        const lowerUrl = url.toLowerCase();

        // Check for suspicious patterns
        const suspiciousPatterns = [
            { pattern: /\.tk$|\.ml$|\.ga$|\.cf$/i, message: 'Suspicious TLD detected' },
            { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, message: 'IP address instead of domain' },
            { pattern: /[^\x20-\x7E]/g, message: 'Non-ASCII characters detected' },
            { pattern: /\.{2,}/g, message: 'Multiple consecutive dots' },
            { pattern: /--/g, message: 'Double hyphens detected' }
        ];

        suspiciousPatterns.forEach(({ pattern, message }) => {
            if (pattern.test(url)) {
                issues.push(message);
            }
        });

        return issues;
    }

    /**
     * Input Sanitization for Forms
     */
    sanitizeInput(input, type = 'text') {
        if (!input || typeof input !== 'string') return '';
        
        let sanitized = input.trim();
        
        // Length validation
        if (sanitized.length > this.maxInputLength) {
            sanitized = sanitized.substring(0, this.maxInputLength);
            if (window.logger) {
                window.logger.warn('Input truncated due to length', { originalLength: input.length }, 'SECURITY');
            }
        }

        switch (type) {
            case 'url':
                return this.sanitizeUrl(sanitized);
            
            case 'text':
                return this.sanitizeText(sanitized);
            
            case 'email':
                return this.sanitizeEmail(sanitized);
            
            default:
                return this.sanitizeText(sanitized);
        }
    }

    sanitizeText(text) {
        return text
            .replace(/[<>]/g, '') // Remove HTML brackets
            .replace(/['"]/g, '') // Remove quotes
            .replace(/[\x00-\x1F\x7F]/g, '') // Remove control characters
            .replace(/javascript:/gi, '') // Remove javascript
            .replace(/on\w+=/gi, ''); // Remove event handlers
    }

    sanitizeEmail(email) {
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const sanitized = this.sanitizeText(email);
        
        if (!emailPattern.test(sanitized)) {
            if (window.logger) {
                window.logger.warn('Invalid email format detected', { email: sanitized }, 'SECURITY');
            }
            return '';
        }
        
        return sanitized;
    }

    /**
     * HTML Sanitization
     */
    sanitizeHtml(html) {
        if (!html || typeof html !== 'string') return '';
        
        // Create a temporary element to safely parse HTML
        const temp = document.createElement('div');
        temp.textContent = html; // This automatically escapes HTML
        
        return temp.innerHTML
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
            .replace(/javascript:/gi, '') // Remove javascript protocol
            .replace(/on\w+\s*=/gi, '') // Remove event handlers
            .replace(/<iframe\b[^>]*>/gi, '') // Remove iframes
            .replace(/<object\b[^>]*>/gi, '') // Remove objects
            .replace(/<embed\b[^>]*>/gi, ''); // Remove embeds
    }

    /**
     * XSS Protection
     */
    preventXss(content) {
        if (typeof content !== 'string') return content;
        
        const xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<iframe\b[^>]*>/gi,
            /<object\b[^>]*>/gi,
            /<embed\b[^>]*>/gi,
            /<link\b[^>]*>/gi,
            /<meta\b[^>]*>/gi
        ];

        let cleaned = content;
        xssPatterns.forEach(pattern => {
            cleaned = cleaned.replace(pattern, '');
        });

        return cleaned;
    }

    /**
     * Rate Limiting
     */
    createRateLimiter(maxRequests, windowMs) {
        const requests = new Map();
        
        return (identifier) => {
            const now = Date.now();
            const windowStart = now - windowMs;
            
            // Clean old entries
            if (requests.has(identifier)) {
                const userRequests = requests.get(identifier).filter(time => time > windowStart);
                requests.set(identifier, userRequests);
            }
            
            const userRequests = requests.get(identifier) || [];
            
            if (userRequests.length >= maxRequests) {
                if (window.logger) {
                    window.logger.warn('Rate limit exceeded', { identifier, count: userRequests.length }, 'SECURITY');
                }
                return false;
            }
            
            userRequests.push(now);
            requests.set(identifier, userRequests);
            return true;
        };
    }

    /**
     * Secure Storage Helpers
     */
    async secureStore(key, value) {
        try {
            // Validate key
            if (typeof key !== 'string' || key.length === 0 || key.length > 100) {
                throw new Error('Invalid storage key');
            }
            
            // Sanitize value if it's a string
            if (typeof value === 'string') {
                value = this.sanitizeInput(value);
            }
            
            // Validate data size
            const serialized = JSON.stringify({ [key]: value });
            if (serialized.length > chrome.storage.local.QUOTA_BYTES_PER_ITEM) {
                throw new Error('Data exceeds storage quota');
            }
            
            await chrome.storage.local.set({ [key]: value });
            
            if (window.logger) {
                window.logger.debug('Secure storage write', { key, size: serialized.length }, 'SECURITY');
            }
            
            return true;
        } catch (error) {
            if (window.logger) {
                window.logger.error('Secure storage failed', error, 'SECURITY');
            }
            return false;
        }
    }

    async secureRetrieve(key) {
        try {
            if (typeof key !== 'string' || key.length === 0 || key.length > 100) {
                throw new Error('Invalid storage key');
            }
            
            const result = await chrome.storage.local.get([key]);
            return result[key] || null;
        } catch (error) {
            if (window.logger) {
                window.logger.error('Secure retrieval failed', error, 'SECURITY');
            }
            return null;
        }
    }

    /**
     * List Validation (for whitelists)
     */
    validateList(list, maxSize = null) {
        const errors = [];
        maxSize = maxSize || this.maxListSize;
        
        if (!Array.isArray(list)) {
            errors.push('List must be an array');
            return { valid: false, errors, sanitized: [] };
        }
        
        if (list.length > maxSize) {
            errors.push(`List exceeds maximum size of ${maxSize} items`);
            return { 
                valid: false, 
                errors, 
                sanitized: list.slice(0, maxSize) 
            };
        }
        
        const sanitized = [];
        const seen = new Set();
        
        for (let i = 0; i < list.length; i++) {
            const item = list[i];
            
            if (typeof item !== 'string') {
                errors.push(`Item at index ${i} must be a string`);
                continue;
            }
            
            const urlValidation = this.validateUrl(item);
            if (!urlValidation.valid) {
                errors.push(`Item at index ${i}: ${urlValidation.errors.join(', ')}`);
                continue;
            }
            
            const sanitizedItem = urlValidation.sanitized;
            
            // Check for duplicates
            if (seen.has(sanitizedItem)) {
                errors.push(`Duplicate item at index ${i}: ${sanitizedItem}`);
                continue;
            }
            
            seen.add(sanitizedItem);
            sanitized.push(sanitizedItem);
        }
        
        return {
            valid: errors.length === 0,
            errors,
            sanitized
        };
    }

    /**
     * Content Security Policy Helpers
     */
    createSecureElement(tagName, attributes = {}) {
        const element = document.createElement(tagName);
        
        // Whitelist of safe attributes
        const safeAttributes = {
            'class': true,
            'id': true,
            'style': true,
            'src': true,
            'href': true,
            'alt': true,
            'title': true,
            'data-*': true
        };
        
        Object.keys(attributes).forEach(attr => {
            const value = attributes[attr];
            
            if (safeAttributes[attr] || attr.startsWith('data-')) {
                if (attr === 'src' || attr === 'href') {
                    const urlValidation = this.validateUrl(value);
                    if (urlValidation.valid) {
                        element.setAttribute(attr, urlValidation.sanitized);
                    }
                } else {
                    element.setAttribute(attr, this.sanitizeInput(value));
                }
            }
        });
        
        return element;
    }

    /**
     * Security Audit
     */
    performSecurityAudit() {
        const audit = {
            timestamp: new Date().toISOString(),
            status: 'PASS',
            issues: [],
            warnings: []
        };
        
        // Check for dangerous globals
        if (typeof eval !== 'undefined') {
            audit.warnings.push('eval function is available');
        }
        
        // Check CSP
        const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        if (!csp) {
            audit.warnings.push('No Content Security Policy detected');
        }
        
        // Check for inline scripts
        const inlineScripts = document.querySelectorAll('script:not([src])');
        if (inlineScripts.length > 0) {
            audit.warnings.push(`${inlineScripts.length} inline script(s) detected`);
        }
        
        // Check for external resources
        const externalResources = document.querySelectorAll('[src^="http"], [href^="http"]');
        if (externalResources.length > 0) {
            audit.warnings.push(`${externalResources.length} external resource(s) detected`);
        }
        
        if (audit.warnings.length > 5) {
            audit.status = 'FAIL';
            audit.issues.push('Too many security warnings');
        }
        
        if (window.logger) {
            window.logger.info('Security audit completed', audit, 'SECURITY');
        }
        
        return audit;
    }
}

// Global security instance
window.PhishySecurity = PhishySecurity;

// Initialize global security if in extension context
if (typeof chrome !== 'undefined' && chrome.runtime) {
    window.security = new PhishySecurity();
}

// Rate limiters for common operations
if (window.security) {
    window.security.apiRateLimit = window.security.createRateLimiter(60, 60000); // 60 requests per minute
    window.security.uiRateLimit = window.security.createRateLimiter(30, 10000); // 30 requests per 10 seconds
}