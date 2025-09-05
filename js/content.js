class PhishyContentScript {
    constructor() {
        this.isProtectionActive = true;
        this.checkedLinks = new Set();
        this.observer = null;
        this.init();
    }

    async init() {
        // Inject styles first
        this.injectStyles();
        
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