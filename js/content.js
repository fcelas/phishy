class PhishyContentScript {
    constructor() {
        this.isProtectionActive = true;
        this.checkedLinks = new Set();
        this.observer = null;
        this.init();
    }

    async init() {
        console.log('🛡️ Phishy content script initializing...');
        
        // Check if extension context is valid
        if (!chrome || !chrome.runtime) {
            console.warn('🛡️ Chrome runtime not available, extension context may be invalid');
            return;
        }

        try {
            // Test if we can access chrome.runtime
            if (!chrome.runtime.id) {
                console.warn('🛡️ Extension context invalidated, stopping initialization');
                return;
            }
        } catch (error) {
            console.warn('🛡️ Extension context error:', error);
            return;
        }
        
        // Inject styles first
        this.injectStyles();
        
        // Get protection status from storage with error handling
        try {
            const result = await chrome.storage.sync.get(['protectionEnabled']);
            this.isProtectionActive = result.protectionEnabled !== false;
            console.log('🛡️ Protection status:', this.isProtectionActive);
        } catch (error) {
            console.warn('🛡️ Could not get protection status:', error);
            this.isProtectionActive = true; // Default to enabled
        }

        if (this.isProtectionActive) {
            this.startLinkDetection();
        }

        // Listen for protection toggle changes with error handling
        try {
            if (chrome && chrome.runtime && chrome.runtime.onMessage) {
                chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
                    if (request.action === 'toggleProtection') {
                        this.isProtectionActive = request.enabled;
                        if (this.isProtectionActive) {
                            this.startLinkDetection();
                        } else {
                            this.stopLinkDetection();
                        }
                    }
                });
            }
        } catch (error) {
            console.warn('Phishy: Could not add runtime message listener:', error);
        }

        // Send current page URL to popup
        this.sendPageInfo();
    }

    startLinkDetection() {
        // Check context validity before starting
        if (!this.isExtensionContextValid()) {
            console.warn('🛡️ Extension context invalid, cannot start link detection');
            return;
        }

        // Initial scan of existing links and text URLs
        this.scanExistingLinks();
        this.scanTextUrls();

        // Set up mutation observer for dynamically added links
        this.observer = new MutationObserver((mutations) => {
            // Check context validity on each mutation
            if (!this.isExtensionContextValid()) {
                console.warn('🛡️ Extension context invalidated during mutation, stopping observer');
                this.stopLinkDetection();
                return;
            }

            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        this.checkNodeForLinks(node);
                        this.checkNodeForTextUrls(node);
                    }
                });
            });
        });

        this.observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    isExtensionContextValid() {
        try {
            return chrome && chrome.runtime && chrome.runtime.id;
        } catch (error) {
            return false;
        }
    }

    stopLinkDetection() {
        if (this.observer) {
            this.observer.disconnect();
            this.observer = null;
        }
        this.checkedLinks.clear();
    }

    scanExistingLinks() {
        const links = document.querySelectorAll('a[href]');
        console.log(`🔍 Scanning ${links.length} existing links on page`);
        links.forEach(link => this.processLink(link));
    }

    scanTextUrls() {
        console.log(`🔍 Scanning for text URLs on page`);
        
        // Get all text nodes that might contain URLs
        const textNodes = this.getAllTextNodes(document.body);
        let urlsFound = 0;
        
        textNodes.forEach(node => {
            const urls = this.extractUrlsFromText(node.textContent);
            if (urls.length > 0) {
                urlsFound += urls.length;
                this.processTextUrls(node, urls);
            }
        });
        
        console.log(`🔍 Found ${urlsFound} text URLs on page`);
    }

    checkNodeForLinks(node) {
        if (node.tagName === 'A' && node.href) {
            this.processLink(node);
        }

        const links = node.querySelectorAll && node.querySelectorAll('a[href]');
        if (links) {
            links.forEach(link => this.processLink(link));
        }
    }

    checkNodeForTextUrls(node) {
        // Get text nodes from the new node
        const textNodes = this.getAllTextNodes(node);
        
        textNodes.forEach(textNode => {
            const urls = this.extractUrlsFromText(textNode.textContent);
            if (urls.length > 0) {
                this.processTextUrls(textNode, urls);
            }
        });
    }

    getAllTextNodes(element) {
        const textNodes = [];
        const walker = document.createTreeWalker(
            element,
            NodeFilter.SHOW_TEXT,
            {
                acceptNode: function(node) {
                    // Skip script and style elements, and elements that already have phishy highlights
                    const parent = node.parentElement;
                    if (parent && (
                        parent.tagName === 'SCRIPT' || 
                        parent.tagName === 'STYLE' ||
                        parent.tagName === 'A' || // Skip links as they're handled separately
                        parent.classList.contains('phishy-text-url-highlight') ||
                        parent.closest('.phishy-modal')
                    )) {
                        return NodeFilter.FILTER_REJECT;
                    }
                    
                    // Only process nodes with meaningful text
                    if (node.textContent.trim().length > 0) {
                        return NodeFilter.FILTER_ACCEPT;
                    }
                    
                    return NodeFilter.FILTER_REJECT;
                }
            }
        );
        
        let currentNode;
        while (currentNode = walker.nextNode()) {
            textNodes.push(currentNode);
        }
        
        return textNodes;
    }

    extractUrlsFromText(text) {
        const urls = new Set();
        
        // Multiple regex patterns to catch different URL formats
        const patterns = [
            // 1. Standard URLs with protocol
            /https?:\/\/(?:[-\w.])+(?::[0-9]+)?(?:\/[^\s<>"{}|\\^`[\]]*)?/gi,
            
            // 2. www. domains
            /www\.(?:[-\w.])+\.(?:[a-z]{2,}|xn--[a-z0-9]+)(?::[0-9]+)?(?:\/[^\s<>"{}|\\^`[\]]*)?/gi,
            
            // 3. Domains without www or protocol (most comprehensive)
            /(?:^|[\s\(])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,}|xn--[a-z0-9]+))(?::[0-9]+)?(?:\/[^\s<>"{}|\\^`[\]]*)?/gi,
            
            // 4. IP addresses (IPv4)
            /(?:^|[\s\(])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::[0-9]+)?(?:\/[^\s<>"{}|\\^`[\]]*)?/gi,
            
            // 5. Subdomains and complex domains
            /(?:^|[\s\(])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.(?:com|net|org|edu|gov|mil|int|info|biz|name|pro|museum|coop|aero|[a-z]{2,}|xn--[a-z0-9]+))(?::[0-9]+)?(?:\/[^\s<>"{}|\\^`[\]]*)?/gi,
            
            // 6. Special TLDs and newer domains
            /(?:^|[\s\(])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:app|dev|io|sh|pw|space|tech|online|site|website|store|blog|news|media|tv|fm|am|to|me|cc|tk|ml|ga|cf))(?::[0-9]+)?(?:\/[^\s<>"{}|\\^`[\]]*)?/gi
        ];
        
        // Apply each pattern
        patterns.forEach(pattern => {
            let match;
            while ((match = pattern.exec(text)) !== null) {
                let url = match[1] || match[0];
                url = url.trim();
                
                // Clean up captured groups
                if (url.startsWith(' ') || url.startsWith('(')) {
                    url = url.substring(1);
                }
                
                // Skip very short matches
                if (url.length < 4) continue;
                
                // Skip if it looks like a file extension or number
                if (/^\d+\.\d+$/.test(url) || /^\w{1,3}$/.test(url)) continue;
                
                urls.add(url.toLowerCase());
            }
        });
        
        // Convert to array and validate
        return Array.from(urls)
            .map(url => {
                // Add protocol if missing
                if (!url.startsWith('http://') && !url.startsWith('https://')) {
                    // Check if it looks like an IP
                    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
                        url = 'http://' + url;
                    } else {
                        url = 'https://' + url;
                    }
                }
                return url;
            })
            .filter(url => {
                try {
                    const urlObj = new URL(url);
                    const hostname = urlObj.hostname;
                    
                    // Skip localhost and private IPs
                    if (hostname === 'localhost' || 
                        hostname.startsWith('127.') ||
                        hostname.startsWith('192.168.') ||
                        hostname.startsWith('10.') ||
                        /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname)) {
                        return false;
                    }
                    
                    // Must have at least one dot (except for special cases)
                    if (!hostname.includes('.') && !hostname.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                        return false;
                    }
                    
                    return true;
                } catch {
                    return false;
                }
            })
            .filter(url => !this.isInternalLink(url)); // Skip internal URLs
    }

    async processTextUrls(textNode, urls) {
        for (const url of urls) {
            // Skip if already checked
            if (this.checkedLinks.has(url)) {
                continue;
            }
            
            this.checkedLinks.add(url);
            
            try {
                // Extract domain for analysis
                const domain = new URL(url).hostname;
                console.log(`🔗 Analyzing text URL: ${domain} (${url})`);
                
                // Send to background script for analysis
                const response = await this.sendMessageWithRetry({
                    action: 'analyzeUrl',
                    url: domain
                });

                console.log(`📊 Analysis result for text URL ${domain}:`, response);

                if (response && response.isMalicious) {
                    console.log(`🚨 Malicious text URL detected: ${domain}`);
                    this.handleMaliciousTextUrl(textNode, url, response);
                } else if (response && response.error && response.error.includes('quota exceeded')) {
                    console.log(`⚠️ API quota exceeded for text URL: ${domain} - protection may be limited`);
                    // Still show as potentially suspicious due to rate limiting
                    this.handleMaliciousTextUrl(textNode, url, {
                        threatType: 'rate_limited',
                        confidence: 50,
                        source: 'rate_limit'
                    });
                } else {
                    console.log(`✅ Safe text URL: ${domain}`);
                }
            } catch (error) {
                console.error('Phishy: Error processing text URL:', error);
            }
        }
    }

    handleMaliciousTextUrl(textNode, maliciousUrl, analysisResult) {
        try {
            const parent = textNode.parentElement;
            if (!parent) return;

            // Create a new version of the text with the malicious URL highlighted
            const originalText = textNode.textContent;
            let urlToHighlight = maliciousUrl.replace(/^https?:\/\//, ''); // Remove protocol for matching
            let urlIndex = -1;
            
            // Try multiple matching strategies
            const matchingStrategies = [
                urlToHighlight, // Without protocol
                maliciousUrl, // Full URL
                maliciousUrl.replace(/^https:\/\//, 'www.'), // Replace https with www
                urlToHighlight.replace(/^www\./, ''), // Remove www
                new URL(maliciousUrl).hostname // Just the hostname
            ];
            
            for (const strategy of matchingStrategies) {
                const index = originalText.toLowerCase().indexOf(strategy.toLowerCase());
                if (index !== -1) {
                    urlToHighlight = originalText.substring(index, index + strategy.length);
                    urlIndex = index;
                    break;
                }
            }
            
            // If still not found, try a more flexible approach
            if (urlIndex === -1) {
                const hostname = new URL(maliciousUrl).hostname;
                const hostnameIndex = originalText.toLowerCase().indexOf(hostname.toLowerCase());
                if (hostnameIndex !== -1) {
                    urlToHighlight = originalText.substring(hostnameIndex, hostnameIndex + hostname.length);
                    urlIndex = hostnameIndex;
                }
            }
            
            if (urlIndex !== -1) {
                this.highlightUrlInText(textNode, urlToHighlight, urlIndex, analysisResult);
                // Update statistics
                this.updateStats('block');
                console.log(`🔴 Phishy: Malicious text URL highlighted - ${urlToHighlight} from ${maliciousUrl}`);
            } else {
                console.warn(`🔴 Could not find URL to highlight: ${maliciousUrl} in text: ${originalText}`);
            }
        } catch (error) {
            console.error('Error highlighting malicious text URL:', error);
        }
    }

    highlightUrlInText(textNode, urlText, startIndex, analysisResult) {
        const parent = textNode.parentElement;
        const originalText = textNode.textContent;
        
        // Split the text into parts: before, URL, after
        const beforeText = originalText.substring(0, startIndex);
        const afterText = originalText.substring(startIndex + urlText.length);
        
        // Create new elements
        const beforeSpan = document.createTextNode(beforeText);
        const urlSpan = document.createElement('span');
        const afterSpan = document.createTextNode(afterText);
        
        // Style the malicious URL span
        urlSpan.className = 'phishy-text-url-highlight phishy-malicious-highlight';
        urlSpan.textContent = urlText;
        urlSpan.title = `⚠️ URL maliciosa detectada: ${analysisResult.threatType || 'Ameaça'} (${analysisResult.confidence || 'N/A'}% confiança)`;
        
        // Make it clickable to show warning
        urlSpan.style.cursor = 'pointer';
        urlSpan.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.showTextUrlWarning(urlText, analysisResult);
        });
        
        // Replace the original text node with the new elements
        parent.insertBefore(beforeSpan, textNode);
        parent.insertBefore(urlSpan, textNode);
        parent.insertBefore(afterSpan, textNode);
        parent.removeChild(textNode);
    }

    showTextUrlWarning(url, analysisResult) {
        const modal = document.createElement('div');
        modal.className = 'phishy-modal';
        modal.innerHTML = `
            <div class="phishy-modal-content">
                <div class="phishy-modal-header">
                    <h3>⚠️ URL Maliciosa Detectada</h3>
                    <button class="phishy-close-btn">&times;</button>
                </div>
                <div class="phishy-modal-body">
                    <p><strong>URL:</strong> ${this.sanitizeHtml(url)}</p>
                    <p><strong>Tipo de Ameaça:</strong> ${this.sanitizeHtml(analysisResult.threatType || 'Desconhecida')}</p>
                    <p><strong>Confiança:</strong> ${this.sanitizeHtml(analysisResult.confidence || 'N/A')}%</p>
                    <p><strong>Aviso:</strong> Esta URL foi detectada como maliciosa e pode ser perigosa.</p>
                    <div class="phishy-modal-actions">
                        <button class="phishy-btn phishy-btn-danger phishy-cancel-btn">
                            Entendi
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Add event listeners
        const closeBtn = modal.querySelector('.phishy-close-btn');
        const cancelBtn = modal.querySelector('.phishy-cancel-btn');
        
        const closeModal = () => document.body.removeChild(modal);
        
        closeBtn.addEventListener('click', closeModal);
        cancelBtn.addEventListener('click', closeModal);
        
        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });

        document.body.appendChild(modal);
    }

    async processLink(linkElement) {
        const url = linkElement.href;
        
        // Skip if already checked or is internal link
        if (this.checkedLinks.has(url) || this.isInternalLink(url)) {
            return;
        }

        this.checkedLinks.add(url);

        try {
            // Check if chrome.runtime is available
            if (!chrome || !chrome.runtime || !chrome.runtime.sendMessage) {
                console.warn('Phishy: Chrome runtime not available, skipping link analysis');
                return;
            }

            // Extract domain for analysis
            const domain = new URL(url).hostname;
            console.log(`🔗 Analyzing link: ${domain} (${url})`);
            
            // Send to background script for VirusTotal analysis with timeout
            const response = await this.sendMessageWithRetry({
                action: 'analyzeUrl',
                url: domain
            });

            console.log(`📊 Analysis result for ${domain}:`, response);

            if (response && response.isMalicious) {
                console.log(`🚨 Malicious link detected: ${domain}`);
                this.handleMaliciousLink(linkElement, response);
            } else if (response && response.error && response.error.includes('quota exceeded')) {
                console.log(`⚠️ API quota exceeded for link: ${domain} - protection may be limited`);
                // Show a subtle warning for rate limited URLs
                this.handleRateLimitedLink(linkElement, domain);
            } else {
                console.log(`✅ Safe link: ${domain}`);
            }
        } catch (error) {
            console.error('Phishy: Error processing link:', error);
        }
    }

    async sendMessageWithRetry(message, maxRetries = 3) {
        for (let i = 0; i < maxRetries; i++) {
            try {
                return await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => {
                        reject(new Error('Message timeout'));
                    }, 5000);

                    chrome.runtime.sendMessage(message, (response) => {
                        clearTimeout(timeout);
                        if (chrome.runtime.lastError) {
                            reject(new Error(chrome.runtime.lastError.message));
                        } else {
                            resolve(response);
                        }
                    });
                });
            } catch (error) {
                console.warn(`Phishy: Attempt ${i + 1} failed:`, error.message);
                if (i === maxRetries - 1) {
                    throw error;
                }
                // Wait before retry
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
    }

    isInternalLink(url) {
        try {
            const linkDomain = new URL(url).hostname;
            const currentDomain = window.location.hostname;
            return linkDomain === currentDomain;
        } catch {
            return true; // Assume internal if URL is malformed
        }
    }

    handleMaliciousLink(linkElement, analysisResult) {
        // Add warning classes for red highlight
        linkElement.classList.add('phishy-warning', 'phishy-malicious-highlight');
        
        // Add data attribute for threat info
        linkElement.setAttribute('data-phishy-threat', analysisResult.threatType || 'suspicious');
        linkElement.setAttribute('data-phishy-confidence', analysisResult.confidence || '0');
        
        // Create warning badge
        const warningBadge = document.createElement('span');
        warningBadge.className = 'phishy-threat-badge';
        warningBadge.innerHTML = '🚨';
        warningBadge.title = `Ameaça detectada: ${analysisResult.threatType || 'Suspeito'} (${analysisResult.confidence || 'N/A'}% confiança)`;
        
        // Insert badge before the link text
        if (linkElement.firstChild) {
            linkElement.insertBefore(warningBadge, linkElement.firstChild);
        } else {
            linkElement.appendChild(warningBadge);
        }

        // Block click and show detailed warning
        const originalHref = linkElement.href;
        linkElement.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.showDetailedWarning(originalHref, analysisResult);
        }, { capture: true });
        
        // Also block other navigation events
        linkElement.addEventListener('auxclick', (e) => {
            e.preventDefault();
            e.stopPropagation();
        }, { capture: true });

        // Update statistics
        this.updateStats('block');
        
        console.log(`🔴 Phishy: Malicious link blocked and highlighted - ${originalHref}`);
    }

    handleRateLimitedLink(linkElement, domain) {
        // Add a subtle warning class for rate limited links
        linkElement.classList.add('phishy-rate-limited');
        
        // Create a subtle warning badge
        const rateLimitBadge = document.createElement('span');
        rateLimitBadge.className = 'phishy-rate-limit-badge';
        rateLimitBadge.innerHTML = '⏱️';
        rateLimitBadge.title = `Proteção limitada: Análise de ${domain} foi limitada devido ao limite de requisições da API. A URL pode precisar de verificação manual.`;
        rateLimitBadge.style.cssText = `
            font-size: 12px;
            margin-left: 4px;
            opacity: 0.7;
            cursor: help;
        `;
        
        // Insert badge after the link text
        linkElement.appendChild(rateLimitBadge);
        
        console.log(`⏱️ Phishy: Rate limited link marked for manual verification - ${domain}`);
    }

    showDetailedWarning(url, analysisResult) {
        const modal = document.createElement('div');
        modal.className = 'phishy-modal';
        modal.innerHTML = `
            <div class="phishy-modal-content">
                <div class="phishy-modal-header">
                    <h3>⚠️ Link Bloqueado</h3>
                    <button class="phishy-close-btn">&times;</button>
                </div>
                <div class="phishy-modal-body">
                    <p><strong>URL:</strong> ${this.sanitizeHtml(url)}</p>
                    <p><strong>Ameaça:</strong> ${this.sanitizeHtml(analysisResult.threatType || 'Desconhecida')}</p>
                    <p><strong>Confiança:</strong> ${this.sanitizeHtml(analysisResult.confidence || 'N/A')}%</p>
                    <div class="phishy-modal-actions">
                        <button class="phishy-btn phishy-btn-danger phishy-cancel-btn">
                            Cancelar
                        </button>
                        <button class="phishy-btn phishy-btn-warning phishy-proceed-btn">
                            Prosseguir Mesmo Assim
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Close button handler
        const closeBtn = modal.querySelector('.phishy-close-btn');
        const cancelBtn = modal.querySelector('.phishy-cancel-btn');
        const proceedBtn = modal.querySelector('.phishy-proceed-btn');
        
        const closeModal = () => {
            if (modal.parentNode) {
                modal.parentNode.removeChild(modal);
            }
        };
        
        closeBtn.addEventListener('click', closeModal);
        cancelBtn.addEventListener('click', closeModal);
        
        // Background click to close
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });

        // Proceed button handler
        proceedBtn.addEventListener('click', () => {
            closeModal();
            window.open(url, '_blank');
        });
    }

    sanitizeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    updateStats(type) {
        try {
            if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
                chrome.runtime.sendMessage({
                    action: 'updateStats',
                    type: type,
                    domain: window.location.hostname
                }).catch(error => {
                    console.warn('Phishy: Could not update stats:', error.message);
                });
            }
        } catch (error) {
            console.warn('Phishy: Chrome runtime not available for stats update:', error);
        }
    }

    sendPageInfo() {
        try {
            if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
                chrome.runtime.sendMessage({
                    action: 'pageInfo',
                    url: window.location.hostname,
                    fullUrl: window.location.href
                }).catch(error => {
                    console.warn('Phishy: Could not send page info:', error.message);
                });
            }
        } catch (error) {
            console.warn('Phishy: Chrome runtime not available for page info:', error);
        }
    }

    injectStyles() {
        if (document.getElementById('phishy-styles')) return;

        const style = document.createElement('style');
        style.id = 'phishy-styles';
        style.textContent = `
            /* Red highlight for malicious links - like a highlighter marker */
            .phishy-malicious-highlight {
                background: linear-gradient(120deg, #ff4757 0%, #ff3742 100%) !important;
                color: white !important;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.5) !important;
                padding: 3px 8px !important;
                margin: 0 2px !important;
                border-radius: 6px !important;
                border: 2px solid #ff1744 !important;
                box-shadow: 0 3px 10px rgba(255, 71, 87, 0.5) !important;
                text-decoration: none !important;
                font-weight: 700 !important;
                display: inline-block !important;
                transition: all 0.3s ease !important;
                position: relative !important;
                z-index: 100 !important;
                cursor: not-allowed !important;
                min-height: 20px !important;
                line-height: 1.2 !important;
            }
            
            .phishy-malicious-highlight:hover {
                background: linear-gradient(120deg, #ff3742 0%, #ff1744 100%) !important;
                transform: translateY(-1px) !important;
                box-shadow: 0 4px 12px rgba(255, 71, 87, 0.6) !important;
            }
            
            .phishy-malicious-highlight:before {
                content: '';
                position: absolute;
                top: -2px;
                left: -2px;
                right: -2px;
                bottom: -2px;
                background: linear-gradient(45deg, #ff4757, #ff3742, #ff1744, #ff4757);
                border-radius: 6px;
                z-index: -1;
                animation: phishyGlow 2s ease-in-out infinite alternate;
            }
            
            @keyframes phishyGlow {
                from {
                    box-shadow: 0 0 5px rgba(255, 71, 87, 0.4);
                }
                to {
                    box-shadow: 0 0 15px rgba(255, 71, 87, 0.8), 0 0 25px rgba(255, 71, 87, 0.4);
                }
            }
            
            .phishy-threat-badge {
                margin-right: 4px !important;
                font-size: 12px !important;
                animation: phishyPulse 1.5s ease-in-out infinite;
            }
            
            @keyframes phishyPulse {
                0%, 100% {
                    transform: scale(1);
                }
                50% {
                    transform: scale(1.1);
                }
            }

            /* Tooltip for additional threat info */
            .phishy-malicious-highlight:after {
                content: attr(data-phishy-threat) ' - ' attr(data-phishy-confidence) '% confiança';
                position: absolute;
                bottom: 100%;
                left: 50%;
                transform: translateX(-50%);
                background: rgba(0, 0, 0, 0.9);
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: normal;
                white-space: nowrap;
                opacity: 0;
                pointer-events: none;
                transition: opacity 0.2s ease;
                z-index: 1001;
                margin-bottom: 5px;
            }
            
            .phishy-malicious-highlight:hover:after {
                opacity: 1;
            }

            .phishy-warning-content {
                display: flex;
                align-items: center;
                gap: 4px;
            }

            .phishy-modal {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 10000;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }

            .phishy-modal-content {
                background: #0E2A3C;
                color: #F9F3E7;
                padding: 20px;
                border-radius: 8px;
                max-width: 400px;
                width: 90%;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            }

            .phishy-modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
            }

            .phishy-modal-header h3 {
                margin: 0;
                color: #F95840;
            }

            .phishy-close-btn {
                background: none;
                border: none;
                color: #F9F3E7;
                font-size: 24px;
                cursor: pointer;
                padding: 0;
                width: 30px;
                height: 30px;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .phishy-modal-body p {
                margin: 10px 0;
                word-break: break-all;
            }

            /* Text URL highlighting */
            .phishy-text-url-highlight {
                background: linear-gradient(135deg, #F95840 0%, #E45541 50%, #F95840 100%) !important;
                background-size: 200% 200% !important;
                animation: phishy-pulse-bg 2s ease-in-out infinite !important;
                padding: 2px 4px !important;
                border-radius: 3px !important;
                color: #F9F3E7 !important;
                font-weight: 600 !important;
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5) !important;
                position: relative !important;
                display: inline-block !important;
                box-shadow: 0 0 8px rgba(249, 88, 64, 0.4) !important;
                border: 1px solid rgba(249, 88, 64, 0.6) !important;
                text-decoration: underline !important;
            }

            .phishy-text-url-highlight:hover {
                background-size: 100% 100% !important;
                box-shadow: 0 0 12px rgba(249, 88, 64, 0.6) !important;
                transform: scale(1.02) !important;
                transition: all 0.2s ease !important;
            }

            .phishy-text-url-highlight:before {
                content: "🚨" !important;
                margin-right: 2px !important;
                font-size: 10px !important;
            }

            .phishy-modal-actions {
                display: flex;
                gap: 10px;
                margin-top: 20px;
            }

            .phishy-btn {
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-weight: 500;
                flex: 1;
            }

            .phishy-btn-danger {
                background: #666;
                color: white;
            }

            .phishy-btn-warning {
                background: #F95840;
                color: white;
            }

            .phishy-btn:hover {
                opacity: 0.9;
            }
        `;

        document.head.appendChild(style);
    }
}

// Initialize when DOM is ready
console.log('📄 Phishy content script loaded on:', window.location.href);
if (document.readyState === 'loading') {
    console.log('⏳ DOM still loading, waiting...');
    document.addEventListener('DOMContentLoaded', () => {
        console.log('✅ DOM loaded, initializing Phishy...');
        new PhishyContentScript();
    });
} else {
    console.log('✅ DOM ready, initializing Phishy immediately...');
    new PhishyContentScript();
}