# Phishy Extension - Testing Guide

## 🔴 Testing URL Highlighting Feature

A extensão agora destaca URLs maliciosas em **vermelho** como um marca-texto quando ameaças são detectadas.

### Como Testar

#### 1. **Modo Desenvolvimento (Recomendado)**
```bash
# A extensão usa modo demo quando APIs não estão configuradas
# URLs de teste que serão marcadas como maliciosas:
- malicious-site.com
- phishing-example.net  
- suspicious-domain.org
- fake-bank.com
- evil-download.net
```

#### 2. **Teste Manual**
1. Carregue a extensão no Chrome (modo desenvolvedor)
2. Acesse qualquer página web
3. Adicione links de teste em uma página HTML:

```html
<!DOCTYPE html>
<html>
<head><title>Teste Phishy</title></head>
<body>
    <h1>Teste de Links</h1>
    
    <!-- Links seguros (não serão destacados) -->
    <p><a href="https://google.com">Google (Seguro)</a></p>
    <p><a href="https://github.com">GitHub (Seguro)</a></p>
    
    <!-- Links maliciosos (serão destacados em vermelho) -->
    <p><a href="https://malicious-site.com">Link Malicioso 1</a></p>
    <p><a href="https://phishing-example.net">Link de Phishing</a></p>
    <p><a href="https://fake-bank.com/login">Banco Falso</a></p>
    
    <!-- Links dinâmicos (teste de detecção em tempo real) -->
    <button onclick="addMaliciousLink()">Adicionar Link Malicioso</button>
    
    <script>
    function addMaliciousLink() {
        const link = document.createElement('a');
        link.href = 'https://suspicious-domain.org';
        link.textContent = 'Link Suspeito Dinâmico';
        document.body.appendChild(link);
    }
    </script>
</body>
</html>
```

### 🎯 Comportamento Esperado

#### **URLs Maliciosas Detectadas:**
- **Destaque vermelho**: Fundo gradiente vermelho brilhante
- **Badge de alerta**: Emoji 🚨 antes do texto do link  
- **Efeito visual**: Brilho pulsante e sombra
- **Cursor**: Muda para "not-allowed" 
- **Tooltip**: Mostra tipo de ameaça e nível de confiança
- **Bloqueio**: Click é interceptado e mostra modal de aviso

#### **URLs Seguras:**
- Não são modificadas visualmente
- Funcionam normalmente
- Não são bloqueadas

### 🔧 Recursos Visuais

#### **Destaque Vermelho**
- Cor de fundo: Gradiente vermelho (#ff4757 → #ff3742)
- Borda: Vermelha sólida com brilho
- Texto: Branco com sombra
- Animação: Brilho pulsante contínuo

#### **Modal de Aviso**
Quando um link malicioso é clicado:
- **Modal escuro**: Sobreposição em tela cheia
- **Informações da ameaça**: URL, tipo, confiança
- **Botões**: "Cancelar" ou "Prosseguir Mesmo Assim"
- **Tema**: Consistente com a extensão (azul escuro)

### 📊 Logs e Debug

#### **Console do Browser:**
```
🔴 Phishy: Malicious link blocked and highlighted - https://malicious-site.com
```

#### **Popup da Extensão:**
- Estatísticas atualizadas automaticamente
- Contador de links bloqueados incrementa
- Status de proteção visível

### 🧪 Cenários de Teste

#### **Teste 1: Detecção Básica**
- [ ] Links maliciosos são destacados em vermelho
- [ ] Links seguros permanecem normais
- [ ] Badge de alerta aparece

#### **Teste 2: Interação**
- [ ] Click em link malicioso abre modal
- [ ] Modal mostra informações corretas
- [ ] Botão "Cancelar" fecha modal
- [ ] Botão "Prosseguir" abre link em nova aba

#### **Teste 3: Links Dinâmicos**
- [ ] Links adicionados via JavaScript são detectados
- [ ] MutationObserver funciona corretamente
- [ ] Performance não é afetada

#### **Teste 4: Diferentes Contextos**
- [ ] Funciona em diferentes tipos de sites
- [ ] CSS não conflita com estilos da página
- [ ] Z-index adequado (destaque visível)

#### **Teste 5: Toggle de Proteção**
- [ ] Desativar proteção remove destaque
- [ ] Reativar proteção restaura detecção
- [ ] Estado sincroniza entre abas

### ⚡ Performance

#### **Otimizações Implementadas:**
- Cache de links já verificados
- Debounce para links dinâmicos
- Estilos CSS otimizados com hardware acceleration
- Lazy loading de análises

#### **Métricas Esperadas:**
- Tempo de detecção: < 500ms por link
- Impacto na performance: < 5% CPU
- Uso de memória: < 10MB por aba

### 🐛 Troubleshooting

#### **Links não são destacados:**
1. Verificar se proteção está ativa no popup
2. Checar console por erros JavaScript
3. Confirmar se content script foi injetado
4. Verificar configuração de APIs

#### **Estilos CSS não aplicados:**
1. Verificar se `injectStyles()` foi chamado
2. Checar Content Security Policy
3. Confirmar seletor CSS único

#### **Modal não aparece:**
1. Verificar event listeners
2. Checar z-index conflicts
3. Confirmar JavaScript não tem erros

### 🔍 Debug Commands

```javascript
// No console do browser (F12):

// Verificar se content script está ativo
window.PhishyContentScript

// Ver links já verificados
document.querySelectorAll('.phishy-malicious-highlight')

// Forçar re-scan de links
// (precisa recarregar página se content script não está global)

// Verificar estilos injetados
document.getElementById('phishy-styles')
```

Esta funcionalidade transforma a extensão numa ferramenta visual muito mais eficaz, alertando imediatamente os usuários sobre links perigosos com destaque vermelho impossível de ignorar! 🛡️