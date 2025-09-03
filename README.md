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
- API Key do VirusTotal
- API Key do Claude (opcional)

### Passos de Instalação

1. **Clone o repositório**:
   ```bash
   git clone [repository-url]
   cd phishy
   ```

2. **Configurar APIs**:
   - VirusTotal API já está configurada
   - Para Claude AI: substitua `YOUR_CLAUDE_API_KEY_HERE` em `js/background.js` linha 4

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
│   └── styles.css         # Estilos do dashboard
├── js/
│   ├── background.js      # Script principal da extensão
│   ├── content.js         # Script de detecção de links
│   ├── popup.js           # Lógica do dashboard
│   └── claude-api.js      # Integração com Claude AI
├── icons/                 # Ícones da extensão (adicionar)
└── README.md             # Este arquivo
```

## 🔧 Configuração

### API do VirusTotal
A API key já está configurada: `502817565555cdd55c70a2a1e6703ad0913317e524780231732da90c21713897`

### API do Claude (Opcional)
1. Obtenha uma API key do Claude AI
2. Substitua `YOUR_CLAUDE_API_KEY_HERE` em `js/background.js`
3. A extensão funciona sem Claude, mas com relatórios simplificados


## 🎯 Como Usar

1. **Ativar Proteção**: Use o toggle no dashboard
2. **Monitorar Estatísticas**: Veja links bloqueados e taxa de proteção
3. **Visualizar Ameaças**: Principais tipos detectados são exibidos
4. **Configurar Whitelist**: Adicione sites confiáveis (em desenvolvimento)

## 🛡️ Segurança

- Todas as análises são feitas via APIs externas
- Nenhum dado sensível é armazenado localmente
- Links suspeitos são bloqueados preventivamente
- Usuário pode prosseguir por conta própria se desejar

## 🚧 Desenvolvimento

### Próximas Funcionalidades

- [ ] Página de Alertas completa
- [ ] Sistema de Whitelist
- [ ] Configurações avançadas
- [ ] Página de perfil do usuário
- [ ] Exportação de relatórios
- [ ] Integração com mais APIs de segurança

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

## 🤝 Contribuição

Para contribuir:
1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📝 Licença

Este projeto está sob licença MIT. Veja o arquivo LICENSE para detalhes.

## ⚠️ Aviso Legal

Esta extensão é fornecida como está, sem garantias. Use por sua conta e risco. Os desenvolvedores não se responsabilizam por danos causados pelo uso da extensão.