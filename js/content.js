class PhishyContentScript {
    constructor() {
        this.isProtectionActive = true;
        this.checkedLinks = new Set();
        this.observer = null;
        this.init();
    }

    async init() {
        // Get protection status from storage
        const result = await chrome.storage.sync.get(['protectionEnabled']);
        this.isProtectionActive = result.protectionEnabled !== false;

        if (this.isProtectionActive) {
            this.startLinkDetection();
        }

        // Listen for protection toggle changes
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

        // Send current page URL to popup
        this.sendPageInfo();
    }

    startLinkDetection() {
        // Initial scan of existing links
        this.scanExistingLinks();

        // Set up mutation observer for dynamically added links
        this.observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        this.checkNodeForLinks(node);
                    }
                });
            });
        });

        this.observer.observe(document.body, {
            childList: true,
            subtree: true
        });
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
        links.forEach(link => this.processLink(link));
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

    async processLink(linkElement) {
        const url = linkElement.href;
        
        // Skip if already checked or is internal link
        if (this.checkedLinks.has(url) || this.isInternalLink(url)) {
            return;
        }

        this.checkedLinks.add(url);

        try {
            // Extract domain for analysis
            const domain = new URL(url).hostname;
            
            // Send to background script for VirusTotal analysis
            const response = await chrome.runtime.sendMessage({
                action: 'analyzeUrl',
                url: domain
            });

            if (response && response.isMalicious) {
                this.handleMaliciousLink(linkElement, response);
            }
        } catch (error) {
            console.error('Phishy: Error processing link:', error);
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
        // Add warning class
        linkElement.classList.add('phishy-warning');
        
        // Create warning overlay
        const warning = document.createElement('div');
        warning.className = 'phishy-link-warning';
        warning.innerHTML = `
            <div class="phishy-warning-content">
                <span class="phishy-warning-icon">⚠️</span>
                <span class="phishy-warning-text">Link Suspeito</span>
            </div>
        `;

        // Position warning
        linkElement.style.position = 'relative';
        linkElement.appendChild(warning);

        // Block click and show detailed warning
        linkElement.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.showDetailedWarning(linkElement.href, analysisResult);
        });

        // Update statistics
        this.updateStats('block');
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
                    <p><strong>URL:</strong> ${url}</p>
                    <p><strong>Ameaça:</strong> ${analysisResult.threatType || 'Desconhecida'}</p>
                    <p><strong>Confiança:</strong> ${analysisResult.confidence || 'N/A'}</p>
                    <div class="phishy-modal-actions">
                        <button class="phishy-btn phishy-btn-danger" onclick="this.closest('.phishy-modal').remove()">
                            Cancelar
                        </button>
                        <button class="phishy-btn phishy-btn-warning" onclick="this.proceedToLink('${url}')">
                            Prosseguir Mesmo Assim
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Close button handler
        modal.querySelector('.phishy-close-btn').onclick = () => modal.remove();
        modal.onclick = (e) => {
            if (e.target === modal) modal.remove();
        };

        // Proceed button handler
        window.proceedToLink = (url) => {
            modal.remove();
            window.open(url, '_blank');
        };
    }

    updateStats(type) {
        chrome.runtime.sendMessage({
            action: 'updateStats',
            type: type,
            domain: window.location.hostname
        });
    }

    sendPageInfo() {
        chrome.runtime.sendMessage({
            action: 'pageInfo',
            url: window.location.hostname,
            fullUrl: window.location.href
        });
    }

    injectStyles() {
        if (document.getElementById('phishy-styles')) return;

        const style = document.createElement('style');
        style.id = 'phishy-styles';
        style.textContent = `
            .phishy-warning {
                border: 2px solid #F95840 !important;
                background-color: rgba(249, 88, 64, 0.1) !important;
            }

            .phishy-link-warning {
                position: absolute;
                top: -25px;
                left: 0;
                background: #F95840;
                color: white;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 10px;
                font-weight: bold;
                z-index: 1000;
                pointer-events: none;
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
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new PhishyContentScript();
    });
} else {
    new PhishyContentScript();
}