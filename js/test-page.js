let linkCounter = 1;

function addSafeLink() {
    const container = document.getElementById('dynamic-links');
    const link = document.createElement('p');
    link.innerHTML = `<a href="https://example.com/safe-${linkCounter}">Link Seguro Dinâmico ${linkCounter}</a>`;
    container.appendChild(link);
    linkCounter++;
}

function addMaliciousLink() {
    const container = document.getElementById('dynamic-links');
    const maliciousDomains = ['malicious-site.com', 'phishing-example.net', 'suspicious-domain.org'];
    const randomDomain = maliciousDomains[Math.floor(Math.random() * maliciousDomains.length)];
    
    const link = document.createElement('p');
    link.innerHTML = `<a href="https://${randomDomain}/dynamic-${linkCounter}">Link Malicioso Dinâmico ${linkCounter} (${randomDomain})</a>`;
    container.appendChild(link);
    linkCounter++;
}

function addMultipleMaliciousLinks() {
    for (let i = 0; i < 3; i++) {
        setTimeout(() => addMaliciousLink(), i * 500); // Adiciona com delay para testar detecção em tempo real
    }
}

// Configurar event listeners
document.addEventListener('DOMContentLoaded', function() {
    const addSafeBtn = document.getElementById('add-safe-link');
    const addMaliciousBtn = document.getElementById('add-malicious-link');
    const addMultipleBtn = document.getElementById('add-multiple-links');
    
    if (addSafeBtn) addSafeBtn.addEventListener('click', addSafeLink);
    if (addMaliciousBtn) addMaliciousBtn.addEventListener('click', addMaliciousLink);
    if (addMultipleBtn) addMultipleBtn.addEventListener('click', addMultipleMaliciousLinks);
});

// Log para debug
console.log('🧪 Página de teste Phishy carregada');
console.log('📊 Verifique o console para logs da extensão');

// Listener para verificar se a extensão está funcionando
setTimeout(() => {
    const maliciousLinks = document.querySelectorAll('.phishy-malicious-highlight');
    if (maliciousLinks.length > 0) {
        console.log(`✅ Extensão funcionando! ${maliciousLinks.length} links maliciosos detectados`);
    } else {
        console.log('⚠️ Nenhum link malicioso foi destacado - verifique se a extensão está ativa');
    }
}, 3000);