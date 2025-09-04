# Phishy - Anti-Phishing Chrome Extension

Uma extensão de navegador Chrome/Chromium para proteção anti-phishing em tempo real, integrada com VirusTotal e análise de IA.

## 🚀 Funcionalidades

- **Detecção em Tempo Real**: Monitora links na página automaticamente usando DOM
- **Integração VirusTotal**: Verifica URLs contra base de dados de ameaças
- **Análise de IA**: Relatórios inteligentes usando Claude AI (quando configurado)
- **Dashboard Intuitivo**: Interface visual com estatísticas e controles
- **Sistema de Alertas**: Notificações e histórico de ameaças detectadas
- **Whitelist Personalizada**: Permita sites confiáveis
- **Toggle de Proteção**: Ative/desative a proteção conforme necessário

## 📋 Páginas da Extensão

1. **DASHBOARD** - Página inicial com estatísticas e controles ✅
2. **ALERTAS** - Histórico de ameaças detectadas (em desenvolvimento)
3. **DETALHES DO ALERTA** - Informações detalhadas de cada ameaça (em desenvolvimento)
4. **WHITELIST** - Gerenciamento de sites confiáveis (em desenvolvimento)
5. **CONFIGURAÇÕES** - Configurações da extensão (em desenvolvimento)
6. **PERFIL** - Informações do usuário (em desenvolvimento)

## 🛠️ Instalação

### Pré-requisitos
- Google Chrome ou Chromium

### Passos de Instalação

1. **Clone o repositório**:
   ```bash
   git clone [repository-url]
   cd phishy
   ```

3. **Instalar no Chrome**:
   - Abra `chrome://extensions/`
   - Ative "Modo do desenvolvedor"
   - Clique "Carregar sem compactação"
   - Selecione a pasta `phishy`

## 📁 Estrutura do Projeto

```
phishy/
├── manifest.json           # Configuração da extensão
├── popup.html             # Interface do dashboard
├── css/
│   ├── styles.css         # Estilos principais e dashboard
│   ├── alertas.css        # Estilos da página de alertas
│   ├── whitelist.css      # Estilos da página de whitelist
│   └── configuracoes.css  # Estilos da página de configurações
├── js/
│   ├── background.js      # Script principal da extensão
│   ├── content.js         # Script de detecção de links
│   ├── popup.js           # Lógica do dashboard
│   ├── alertas.js         # Lógica da página de alertas
│   ├── whitelist.js       # Lógica da página de whitelist
│   ├── configuracoes.js   # Lógica da página de configurações
│   ├── perfil.js          # Lógica da página de perfil
│   ├── detalhes-alerta.js # Lógica dos detalhes de alertas
│   ├── claude-api.js      # Integração com Claude AI
│   ├── logger.js          # Sistema de logging e troubleshooting
│   └── security.js        # Módulo de segurança e validação
├── pages/
│   ├── alertas.html       # Página de histórico de alertas
│   ├── whitelist.html     # Página de gerenciamento de whitelist
│   ├── configuracoes.html # Página de configurações
│   ├── perfil.html        # Página de perfil do usuário
│   └── detalhes-alerta.html # Página de detalhes de alertas
├── tests/
│   ├── test-runner.html   # Interface para execução de testes
│   ├── test-framework.js  # Framework de testes customizado
│   ├── test-runner.js     # Orquestrador dos testes
│   ├── security.test.js   # Testes de segurança
│   ├── unit.test.js       # Testes unitários
│   └── integration.test.js # Testes de integração
├── icons/
│   └── logo.png           # Ícone da extensão
└── README.md             # Este arquivo
```

### APIs Utilizadas

- **VirusTotal API v2**: Detecção de ameaças
- **Claude AI API**: Análise inteligente de ameaças
- **Chrome Extensions API**: Funcionalidades do navegador

## 📊 Dashboard

O dashboard principal exibe:
- URL atual sendo monitorada
- Número de links bloqueados na página
- Total de bloqueios históricos
- Taxa de proteção (precisão)
- Top 3 tipos de ameaça mais comuns
- Toggle para ativar/desativar proteção

## ⚠️ Aviso Legal

Esta extensão é fornecida como está, sem garantias. Use por sua conta e risco. Os desenvolvedores não se responsabilizam por danos causados pelo uso da extensão.