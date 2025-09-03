class PhishyPerfil {
    constructor() {
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadUserData();
    }

    setupEventListeners() {
        // Back button
        const backBtn = document.getElementById('back-btn');
        if (backBtn) {
            backBtn.addEventListener('click', () => {
                this.navigateBack();
            });
        }

        // Profile button (already on profile page, just reload)
        const profileBtn = document.getElementById('profile-btn');
        if (profileBtn) {
            profileBtn.addEventListener('click', () => {
                window.location.reload();
            });
        }

        // Logout button
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                this.handleLogout();
            });
        }
    }

    loadUserData() {
        // This would typically load user data from storage or API
        // For now, we'll use the placeholder data from the design
        const profileData = {
            name: 'Filipe Cela',
            email: 'rm93830@fiap.com.br',
            plan: 'Phishy PRO',
            initials: 'FC'
        };

        this.renderUserData(profileData);
    }

    renderUserData(data) {
        // Update profile information
        const nameElement = document.querySelector('.profile-name');
        const emailElement = document.querySelector('.profile-email');
        const planElement = document.querySelector('.profile-plan');
        const initialsElement = document.querySelector('.avatar-text');

        if (nameElement) nameElement.textContent = data.name;
        if (emailElement) emailElement.textContent = data.email;
        if (planElement) planElement.textContent = data.plan;
        if (initialsElement) initialsElement.textContent = data.initials;
    }

    navigateBack() {
        // Get the previous page from storage
        chrome.storage.local.get(['previousPage'], (result) => {
            const previousPage = result.previousPage;
            
            if (previousPage) {
                // Navigate back to the specific page
                switch (previousPage) {
                    case 'popup.html':
                        window.location.href = '../popup.html';
                        break;
                    case 'alertas.html':
                        window.location.href = 'alertas.html';
                        break;
                    case 'whitelist.html':
                        window.location.href = 'whitelist.html';
                        break;
                    case 'configuracoes.html':
                        window.location.href = 'configuracoes.html';
                        break;
                    default:
                        window.location.href = '../popup.html';
                }
            } else {
                // Default back to dashboard
                window.location.href = '../popup.html';
            }
        });
    }

    handleLogout() {
        // Show confirmation dialog (placeholder)
        if (confirm('Tem certeza que deseja fazer logout?')) {
            this.showMessage('Logout realizado com sucesso');
            
            // In a real implementation, this would:
            // 1. Clear user session data
            // 2. Reset extension to default state
            // 3. Redirect to login or dashboard
            
            setTimeout(() => {
                window.location.href = '../popup.html';
            }, 1500);
        }
    }

    showMessage(text, type = 'success') {
        // Remove existing message
        const existingMessage = document.querySelector('.message');
        if (existingMessage) {
            existingMessage.remove();
        }

        const message = document.createElement('div');
        message.className = `message ${type}`;
        message.textContent = text;
        document.body.appendChild(message);

        setTimeout(() => {
            if (message.parentNode) {
                message.remove();
            }
        }, 3000);
    }
}

// Global functions
window.navigateBack = function() {
    // Get the previous page from storage
    chrome.storage.local.get(['previousPage'], (result) => {
        const previousPage = result.previousPage;
        
        if (previousPage) {
            // Navigate back to the specific page
            switch (previousPage) {
                case 'popup.html':
                    window.location.href = '../popup.html';
                    break;
                case 'alertas.html':
                    window.location.href = 'alertas.html';
                    break;
                case 'whitelist.html':
                    window.location.href = 'whitelist.html';
                    break;
                case 'configuracoes.html':
                    window.location.href = 'configuracoes.html';
                    break;
                default:
                    window.location.href = '../popup.html';
            }
        } else {
            // Default back to dashboard
            window.location.href = '../popup.html';
        }
    });
};

window.handleLogout = function() {
    if (window.phishyPerfil) {
        window.phishyPerfil.handleLogout();
    }
};

window.navigateToProfile = function() {
    // Already on profile page, do nothing or refresh
    window.location.reload();
};

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 10px;
        left: 50%;
        transform: translateX(-50%);
        background: ${type === 'success' ? '#4CAF50' : type === 'warning' ? '#FF9800' : '#2196F3'};
        color: white;
        padding: 8px 16px;
        border-radius: 4px;
        font-size: 12px;
        z-index: 1000;
        animation: slideDown 0.3s ease;
    `;

    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 3000);
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.phishyPerfil = new PhishyPerfil();
});