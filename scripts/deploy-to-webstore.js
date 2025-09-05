#!/usr/bin/env node

/**
 * Chrome Web Store Deployment Script
 * Automates the deployment process to Chrome Web Store
 */

const fs = require('fs');
const path = require('path');

class WebStoreDeployer {
    constructor() {
        this.appId = process.env.CHROME_WEBSTORE_APP_ID;
        this.clientId = process.env.CHROME_WEBSTORE_CLIENT_ID;
        this.clientSecret = process.env.CHROME_WEBSTORE_CLIENT_SECRET;
        this.refreshToken = process.env.CHROME_WEBSTORE_REFRESH_TOKEN;
        
        this.validateEnvironment();
    }

    validateEnvironment() {
        const requiredVars = [
            'CHROME_WEBSTORE_APP_ID',
            'CHROME_WEBSTORE_CLIENT_ID', 
            'CHROME_WEBSTORE_CLIENT_SECRET',
            'CHROME_WEBSTORE_REFRESH_TOKEN'
        ];

        const missing = requiredVars.filter(v => !process.env[v]);
        
        if (missing.length > 0) {
            console.log('📋 Chrome Web Store Deployment Setup');
            console.log('=====================================');
            console.log('');
            console.log('❌ Missing required environment variables:');
            missing.forEach(v => console.log(`   - ${v}`));
            console.log('');
            console.log('🔧 Setup Instructions:');
            console.log('1. Go to Google Cloud Console: https://console.cloud.google.com/');
            console.log('2. Create a new project or select existing one');
            console.log('3. Enable Chrome Web Store API');
            console.log('4. Create OAuth 2.0 credentials');
            console.log('5. Add these to your GitHub repository secrets:');
            console.log('   - CHROME_WEBSTORE_APP_ID: Your extension ID from Chrome Web Store');
            console.log('   - CHROME_WEBSTORE_CLIENT_ID: OAuth client ID');
            console.log('   - CHROME_WEBSTORE_CLIENT_SECRET: OAuth client secret');
            console.log('   - CHROME_WEBSTORE_REFRESH_TOKEN: OAuth refresh token');
            console.log('');
            console.log('📚 Detailed guide: https://developer.chrome.com/docs/webstore/using_webstore_api/');
            
            if (process.env.NODE_ENV !== 'production') {
                console.log('');
                console.log('⚠️  Running in development mode - deployment skipped');
                return;
            }
            
            process.exit(1);
        }
    }

    async getAccessToken() {
        console.log('🔑 Getting access token...');
        
        try {
            const response = await fetch('https://oauth2.googleapis.com/token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    client_id: this.clientId,
                    client_secret: this.clientSecret,
                    refresh_token: this.refreshToken,
                    grant_type: 'refresh_token'
                })
            });

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(`Failed to get access token: ${data.error_description || data.error}`);
            }

            console.log('✅ Access token obtained');
            return data.access_token;
            
        } catch (error) {
            console.error('❌ Error getting access token:', error.message);
            throw error;
        }
    }

    async uploadPackage(zipPath, accessToken) {
        console.log('📦 Uploading extension package...');
        
        if (!fs.existsSync(zipPath)) {
            throw new Error(`Package not found: ${zipPath}`);
        }

        try {
            const zipData = fs.readFileSync(zipPath);
            
            const response = await fetch(
                `https://www.googleapis.com/upload/chromewebstore/v1.1/items/${this.appId}`,
                {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${accessToken}`,
                        'x-goog-api-version': '2'
                    },
                    body: zipData
                }
            );

            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(`Upload failed: ${result.error?.message || 'Unknown error'}`);
            }

            if (result.uploadState === 'SUCCESS') {
                console.log('✅ Package uploaded successfully');
                return result;
            } else {
                console.log('⚠️  Upload completed with warnings:');
                if (result.itemError) {
                    result.itemError.forEach(error => {
                        console.log(`   - ${error.error_detail}`);
                    });
                }
                return result;
            }
            
        } catch (error) {
            console.error('❌ Error uploading package:', error.message);
            throw error;
        }
    }

    async publishExtension(accessToken) {
        console.log('🚀 Publishing extension...');
        
        try {
            const response = await fetch(
                `https://www.googleapis.com/chromewebstore/v1.1/items/${this.appId}/publish`,
                {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${accessToken}`,
                        'x-goog-api-version': '2'
                    }
                }
            );

            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(`Publish failed: ${result.error?.message || 'Unknown error'}`);
            }

            console.log('✅ Extension published successfully');
            console.log(`📊 Status: ${result.status}`);
            console.log(`🔗 Extension URL: https://chrome.google.com/webstore/detail/${this.appId}`);
            
            return result;
            
        } catch (error) {
            console.error('❌ Error publishing extension:', error.message);
            throw error;
        }
    }

    async deploy(zipPath) {
        console.log('🚀 Starting Chrome Web Store deployment...');
        console.log(`📦 Package: ${zipPath}`);
        console.log(`🆔 App ID: ${this.appId}`);
        console.log('');
        
        try {
            // Step 1: Get access token
            const accessToken = await this.getAccessToken();
            
            // Step 2: Upload package
            const uploadResult = await this.uploadPackage(zipPath, accessToken);
            
            // Step 3: Publish extension (only if upload was successful)
            if (uploadResult.uploadState === 'SUCCESS') {
                const publishResult = await this.publishExtension(accessToken);
                
                console.log('');
                console.log('🎉 Deployment completed successfully!');
                console.log('📈 Extension is now live on Chrome Web Store');
                
                return { upload: uploadResult, publish: publishResult };
            } else {
                console.log('');
                console.log('⚠️  Extension uploaded but not published due to errors');
                console.log('🔧 Please review the warnings above and try again');
                
                return { upload: uploadResult, publish: null };
            }
            
        } catch (error) {
            console.error('');
            console.error('💥 Deployment failed:', error.message);
            console.error('');
            console.error('🔧 Troubleshooting:');
            console.error('1. Check your API credentials');
            console.error('2. Verify extension ID is correct');
            console.error('3. Ensure you have publisher permissions');
            console.error('4. Check Chrome Web Store API quotas');
            
            throw error;
        }
    }
}

// Main execution
async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        console.log('Usage: node deploy-to-webstore.js <path-to-zip-file>');
        console.log('Example: node deploy-to-webstore.js build/phishy-anti-phishing.zip');
        process.exit(1);
    }
    
    const zipPath = args[0];
    const deployer = new WebStoreDeployer();
    
    try {
        await deployer.deploy(zipPath);
    } catch (error) {
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = WebStoreDeployer;