# Phishy Extension - Developer Setup

## Configuration System

The Phishy extension uses a secure configuration management system that supports multiple environments and prevents API keys from being committed to version control.

### Configuration Hierarchy

The configuration system loads settings in the following priority order:

1. **config.local.js** - Local development (highest priority)
2. **config.prod.js** - Production CI/CD generated 
3. **Chrome Storage** - User settings stored locally
4. **Demo Mode** - Fallback with mock data (lowest priority)

### Setting Up for Development

1. **Copy the template configuration:**
   ```bash
   cp config/config.template.js config/config.local.js
   ```

2. **Add your API keys to config.local.js:**
   ```javascript
   virustotal: {
       apiKey: 'YOUR_VIRUSTOTAL_API_KEY_HERE', // Replace with your VT key
       // ... other settings
   },
   claude: {
       apiKey: 'sk-ant-api03-...', // Replace with your Claude key
       // ... other settings  
   }
   ```

3. **The config.local.js file is already configured with the provided Claude API key**

### API Keys Required

#### VirusTotal API Key
- Get your free API key at: https://www.virustotal.com/gui/join-us
- Free tier: 4 requests/minute, 1000 requests/day
- Add to `config.local.js` under `virustotal.apiKey`

#### Claude API Key (Already Configured)
- The extension is already configured with a Claude API key
- Located at: `claude.apiKey` in config.local.js
- Uses Claude-3-Haiku model for fast real-time analysis

### Configuration Features

#### Demo Mode
- Automatically enabled when API keys are missing or invalid
- Uses mock data and simulated responses
- Allows testing all extension features without real API calls
- Fake threats configured in `development.demoMode.fakeThreats`

#### Security Features
- Input validation and sanitization
- Rate limiting for API calls
- Content Security Policy compliance
- XSS protection
- Sensitive data sanitization in logs

#### Performance Settings
- Configurable request timeouts
- Concurrent request limits
- Response caching
- Request debouncing

### File Structure

```
config/
├── .gitignore              # Prevents committing sensitive files
├── config.template.js      # Template with placeholder values
└── config.local.js         # Your local development config (not in git)

js/
├── config-manager.js       # Configuration management system
├── claude-api.js          # Claude AI integration
└── background.js          # Background service worker
```

### Configuration Validation

The system automatically:
- Validates configuration structure
- Sanitizes string inputs
- Warns about missing or invalid API keys
- Falls back to demo mode when needed
- Logs configuration status for debugging

### Debugging Configuration

Enable debug logging in your config:

```javascript
development: {
    debug: {
        verbose: true,
        logApiCalls: true,
        showTimings: true,
        exportLogs: true
    }
}
```

Check the browser console for configuration loading messages:
- `CONFIG: Loading Phishy configuration...`
- `CONFIG: Configuration loaded successfully`
- `CLAUDE_API: Claude API initialized`
- `BACKGROUND: Background service initialized`

### Production Deployment

For production deployment, GitHub Actions will:
1. Use repository secrets `API_VIRUS_TOTAL` and `API_CLAUDE`
2. Generate `config.prod.js` with production API keys
3. Build and package the extension
4. Deploy to Chrome Web Store

### Troubleshooting

#### Extension Not Working
1. Check browser console for error messages
2. Verify API keys are correctly set in config.local.js
3. Ensure config-manager.js loads before other scripts
4. Check if demo mode is active (will show in logs)

#### API Errors
1. Verify API key validity and format
2. Check rate limits (especially VirusTotal)  
3. Ensure network connectivity
4. Review API endpoint URLs in configuration

#### Configuration Not Loading
1. Verify config.local.js syntax (valid JavaScript)
2. Check file permissions
3. Ensure config-manager.js is included in HTML pages
4. Check for CSP violations in browser console

### Files That Should Never Be Committed

The following files contain sensitive data and are excluded from git:
- `config/config.local.js` - Your development API keys
- `config/config.prod.js` - Production API keys (CI/CD generated)
- `*.bak`, `*.backup` - Backup files that might contain keys