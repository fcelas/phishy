# Phishy Extension - Deployment Guide

## 🔐 GitHub Secrets Configuration

Your repository already has the following secrets configured:

### API Secrets
- ✅ `API_CLAUDE` - Claude AI API key for production
- ✅ `API_VIRUS_TOTAL` - VirusTotal API key for production

### Optional Chrome Web Store Secrets
For automated deployment to Chrome Web Store, add these secrets:

- `CHROME_WEBSTORE_APP_ID` - Your extension ID from Chrome Web Store
- `CHROME_WEBSTORE_CLIENT_ID` - Google OAuth client ID
- `CHROME_WEBSTORE_CLIENT_SECRET` - Google OAuth client secret  
- `CHROME_WEBSTORE_REFRESH_TOKEN` - OAuth refresh token

## 🚀 Deployment Process

### Automatic Deployment (Recommended)

The GitHub Actions workflow will automatically:

1. **On every push to main:**
   - Run security checks
   - Validate manifest
   - Generate production config with API keys
   - Build extension package
   - Create deployment artifact

2. **On tag creation (e.g., v1.0.0):**
   - All the above steps
   - Update manifest version
   - Create GitHub release with ZIP file
   - Optionally deploy to Chrome Web Store

### Manual Deployment Steps

1. **Create a release tag:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **The workflow will automatically:**
   - Generate `config.prod.js` with your API keys
   - Package the extension
   - Create a GitHub release
   - Upload the ZIP file

3. **Download and submit to Chrome Web Store:**
   - Go to your GitHub releases
   - Download `phishy-anti-phishing-<commit>.zip`
   - Upload to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole/)

## 🏗️ Build Process Details

### Generated Files

The CI/CD process creates these files:

```
config/config.prod.js        # Production config with real API keys
build/phishy-anti-phishing/  # Clean extension directory
phishy-anti-phishing.zip     # Package ready for Chrome Web Store
```

### Security Features

- ✅ Validates API key formats
- ✅ Removes development files
- ✅ Checks for hardcoded secrets
- ✅ Validates manifest structure
- ✅ Generates secure production config

### Production Configuration

The generated `config.prod.js` includes:

```javascript
virustotal: {
    apiKey: 'YOUR_ACTUAL_VIRUS_TOTAL_KEY', // From API_VIRUS_TOTAL secret
    // Production settings...
},
claude: {
    apiKey: 'sk-ant-api03-...', // From API_CLAUDE secret  
    // Production settings...
}
```

## 🏪 Chrome Web Store Submission

### First Time Setup

1. **Create Chrome Web Store Developer Account:**
   - Go to [Chrome Web Store Developer Console](https://chrome.google.com/webstore/devconsole/)
   - Pay one-time $5 registration fee

2. **Upload Extension:**
   - Click "New Item"
   - Upload the ZIP file from GitHub releases
   - Fill in store listing details

3. **Store Listing Requirements:**
   - **Name**: Phishy - Anti-Phishing Protection
   - **Description**: Real-time anti-phishing protection with VirusTotal integration and AI-powered threat analysis
   - **Category**: Productivity
   - **Screenshots**: Take screenshots of the extension UI
   - **Icons**: Use the provided icons in `icons/` directory

### Automated Chrome Web Store Publishing

For automated publishing, set up these additional secrets:

1. **Get Google API Credentials:**
   ```bash
   # Go to Google Cloud Console
   # Enable Chrome Web Store API
   # Create OAuth 2.0 credentials
   # Get refresh token using oauth2l or similar tool
   ```

2. **Add secrets to GitHub:**
   ```
   CHROME_WEBSTORE_APP_ID=your_extension_id
   CHROME_WEBSTORE_CLIENT_ID=your_oauth_client_id  
   CHROME_WEBSTORE_CLIENT_SECRET=your_oauth_secret
   CHROME_WEBSTORE_REFRESH_TOKEN=your_refresh_token
   ```

3. **Deploy automatically:**
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   # Extension will be automatically published
   ```

## 🔍 Validation Checklist

Before deploying, ensure:

- [ ] All APIs work correctly
- [ ] Extension loads without errors
- [ ] Protection toggle functions
- [ ] Threat detection works
- [ ] All pages navigate properly
- [ ] No console errors
- [ ] Manifest version updated
- [ ] Store listing complete

## 🛠️ Troubleshooting

### Common Issues

**Build fails with API key validation:**
- Check that secrets are properly set in GitHub
- Verify API key formats match expected patterns

**Extension doesn't load in Chrome:**
- Check for manifest errors
- Verify all files are included in build
- Test with Chrome's developer mode

**APIs not working:**
- Confirm API keys are valid and active
- Check network connectivity
- Review Chrome extension permissions

### Debug Commands

```bash
# Test locally before deploying
npm run build  # If you have build scripts

# Validate manifest
node -e "console.log(JSON.parse(require('fs').readFileSync('manifest.json')))"

# Check for hardcoded keys
grep -r "sk-ant-api03" js/
grep -r "YOUR_.*_KEY" js/
```

## 📊 Monitoring

After deployment:

1. **Monitor Chrome Web Store metrics**
2. **Check user reviews and feedback** 
3. **Monitor API usage and costs**
4. **Watch for security alerts**
5. **Track extension performance**

## 🔄 Update Process

For updates:

1. Make changes to code
2. Test thoroughly
3. Commit and push to main
4. Create new version tag: `v1.0.1`
5. GitHub Actions will automatically build and create release
6. Download and submit to Chrome Web Store (or use automated deployment)

## 📞 Support

If you encounter issues:

1. Check GitHub Actions logs
2. Review Chrome Web Store developer console
3. Test extension in Chrome developer mode
4. Check API service status pages