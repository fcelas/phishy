class ClaudeAPI {
    constructor(apiKey = null) {
        this.baseUrl = 'https://api.anthropic.com/v1/messages';
        this.apiKey = apiKey || 'YOUR_CLAUDE_API_KEY_HERE';
        this.isConfigured = this.apiKey !== 'YOUR_CLAUDE_API_KEY_HERE';
        this.version = '2023-06-01';
        this.maxRetries = 3;
        this.requestTimeout = 10000; // 10 seconds
    }

    async analyzeThreat(url, context = {}) {
        if (!this.isConfigured) {
            return this.getFallbackAnalysis(url);
        }

        const prompt = `Analyze this URL for potential phishing threats: ${url}

Context: ${JSON.stringify(context)}

Please provide analysis in this exact JSON format:
{
    "isPhishing": boolean,
    "confidence": number (0-100),
    "riskLevel": "high" | "medium" | "low",
    "threatType": "phishing" | "malware" | "typosquatting" | "suspicious" | "safe",
    "indicators": ["indicator1", "indicator2"],
    "recommendation": "action recommendation"
}`;

        try {
            const response = await this.makeRequest(prompt, { maxTokens: 200 });
            return this.parseAnalysisResponse(response.content[0].text);
        } catch (error) {
            console.error('Claude API Error:', error);
            return this.getFallbackAnalysis(url);
        }
    }

    async generateReport(alertData) {
        if (!this.isConfigured) {
            return this.getFallbackReport(alertData);
        }

        const prompt = `Generate a security report for these threat detection results:

Data: ${JSON.stringify(alertData)}

Provide a professional security report focusing on:
1. Summary of threats detected
2. Risk assessment
3. Recommendations for users

Format as JSON:
{
    "summary": "brief summary",
    "riskAssessment": "risk level explanation", 
    "recommendations": ["rec1", "rec2"],
    "technicalDetails": "technical analysis"
}`;

        try {
            const response = await this.makeRequest(prompt, { maxTokens: 300 });
            return this.parseReportResponse(response.content[0].text);
        } catch (error) {
            console.error('Claude API Error:', error);
            return this.getFallbackReport(alertData);
        }
    }

    async makeRequest(prompt, options = {}) {
        const { maxTokens = 150, temperature = 0.1 } = options;

        for (let attempt = 0; attempt < this.maxRetries; attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this.requestTimeout);

                const response = await fetch(this.baseUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-api-key': this.apiKey,
                        'anthropic-version': this.version
                    },
                    body: JSON.stringify({
                        model: 'claude-3-sonnet-20240229',
                        max_tokens: maxTokens,
                        temperature,
                        messages: [{
                            role: 'user',
                            content: prompt
                        }]
                    }),
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (!response.ok) {
                    throw new Error(`Claude API error: ${response.status}`);
                }

                return await response.json();
            } catch (error) {
                if (attempt === this.maxRetries - 1) {
                    throw error;
                }
                await this.delay(Math.pow(2, attempt) * 1000); // Exponential backoff
            }
        }
    }

    parseAnalysisResponse(text) {
        try {
            // Try to extract JSON from response
            const jsonMatch = text.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
        } catch (error) {
            console.warn('Failed to parse Claude response as JSON:', error);
        }

        // Fallback parsing for non-JSON responses
        const isPhishing = text.toLowerCase().includes('phishing') || text.toLowerCase().includes('malicious');
        let riskLevel = 'medium';
        if (text.toLowerCase().includes('high')) riskLevel = 'high';
        else if (text.toLowerCase().includes('baixo')) riskLevel = 'low';

        return {
            isPhishing,
            confidence: isPhishing ? 75 : 25,
            riskLevel,
            threatType: isPhishing ? 'phishing' : 'safe',
            indicators: this.extractIndicators(text),
            recommendation: isPhishing ? 'Block access to this URL' : 'URL appears safe',
            source: 'claude-ai'
        };
    }

    parseReportResponse(text) {
        try {
            const jsonMatch = text.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
        } catch (error) {
            console.warn('Failed to parse Claude report as JSON:', error);
        }

        return {
            summary: text.substring(0, 200) + '...',
            riskAssessment: 'Análise automática de ameaças detectadas',
            recommendations: ['Mantenha a proteção ativada', 'Evite clicar em links suspeitos'],
            technicalDetails: text,
            source: 'claude-ai'
        };
    }

    extractIndicators(text) {
        const indicators = [];
        const lines = text.split('\n');
        
        for (const line of lines) {
            if (line.includes('•') || line.includes('-') || line.includes('*')) {
                const cleaned = line.replace(/[•\-*]\s*/, '').trim();
                if (cleaned.length > 10 && cleaned.length < 100) {
                    indicators.push(cleaned);
                }
            }
        }

        return indicators.slice(0, 4);
    }

    getFallbackAnalysis(url) {
        // Simple heuristic analysis when Claude is not available
        const suspiciousPatterns = [
            /bit\.ly|tinyurl|t\.co/i,
            /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,
            /[a-z0-9]{20,}/i,
            /paypal.*verify|amazon.*suspend|microsoft.*security/i
        ];

        const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(url));
        
        return {
            isPhishing: isSuspicious,
            confidence: isSuspicious ? 60 : 20,
            riskLevel: isSuspicious ? 'medium' : 'low',
            threatType: isSuspicious ? 'suspicious' : 'safe',
            indicators: isSuspicious ? ['Padrão suspeito detectado na URL'] : [],
            recommendation: isSuspicious ? 'Verificar URL antes de acessar' : 'URL parece segura',
            source: 'heuristic'
        };
    }

    getFallbackReport(alertData) {
        const totalThreats = Object.values(alertData.threatTypes || {}).reduce((a, b) => a + b, 0);
        
        return {
            summary: `Detectadas ${totalThreats} ameaças nos últimos registros.`,
            riskAssessment: totalThreats > 10 ? 'Nível de risco elevado' : 'Nível de risco moderado',
            recommendations: [
                'Manter extensão sempre ativada',
                'Verificar URLs suspeitas antes de acessar',
                'Manter navegador atualizado'
            ],
            technicalDetails: `
As principais categorias de ameaça detectadas incluem:
• Phishing (${alertData.threatTypes.phishing || 0}): Tentativas de roubo de credenciais
• Malware (${alertData.threatTypes.malware || 0}): Software malicioso
• Typosquatting (${alertData.threatTypes.typosquatting || 0}): Domínios similares a sites legítimos

Recomenda-se manter a proteção ativada e exercer cautela ao navegar.`,
            source: 'heuristic'
        };
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    updateApiKey(newApiKey) {
        this.apiKey = newApiKey;
        this.isConfigured = newApiKey && newApiKey !== 'YOUR_CLAUDE_API_KEY_HERE';
    }

    getStatus() {
        return {
            configured: this.isConfigured,
            apiKey: this.apiKey ? `${this.apiKey.substring(0, 8)}...` : 'Not set'
        };
    }
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ClaudeAPI;
} else {
    window.ClaudeAPI = ClaudeAPI;
}