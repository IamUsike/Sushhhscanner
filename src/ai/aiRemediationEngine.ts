import { GoogleGenerativeAI } from '@google/generative-ai';
import { Groq } from 'groq-sdk';

interface Vulnerability {
    id: string;
    type: string;
    severity: string;
    endpoint: string;
    method: string;
    description: string;
    cwe?: string;
    cvss?: string;
    timestamp: string;
    details?: any;
}

export async function generateAIRemediation(vulnerability: Vulnerability): Promise<string> {
    try {
        const provider = process.env.LLM_PROVIDER || 'gemini';
        
        if (provider === 'gemini') {
            const apiKey = process.env.GEMINI_API_KEY;
            if (!apiKey) {
                return generateFallbackRemediation(vulnerability);
            }
            
            const gemini = new GoogleGenerativeAI(apiKey);
            const model = gemini.getGenerativeModel({ 
                model: process.env.GEMINI_MODEL || 'gemini-1.5-flash-latest'
            });
            
            const prompt = `Generate a detailed, actionable remediation plan for a ${vulnerability.severity} severity vulnerability of type ${vulnerability.type} found at endpoint ${vulnerability.endpoint}.

Vulnerability Details:
- Type: ${vulnerability.type}
- Severity: ${vulnerability.severity}
- Endpoint: ${vulnerability.endpoint}
- Method: ${vulnerability.method}
- Description: ${vulnerability.description}
- CWE: ${vulnerability.cwe || 'N/A'}
- CVSS: ${vulnerability.cvss || 'N/A'}

Please provide a comprehensive remediation plan that includes:
1. Immediate actions to mitigate the risk
2. Step-by-step technical remediation steps
3. Code examples or configuration changes needed
4. Best practices to prevent similar vulnerabilities
5. Testing recommendations
6. Timeline for implementation

Format the response as clear, actionable steps that a developer can follow.`;

            const result = await model.generateContent(prompt);
            const response = result.response;
            
            return response.text() || generateFallbackRemediation(vulnerability);
            
        } else if (provider === 'groq') {
            const apiKey = process.env.GROQ_API_KEY;
            if (!apiKey) {
                return generateFallbackRemediation(vulnerability);
            }
            
            const groq = new Groq({ apiKey });
            const chatCompletion = await groq.chat.completions.create({
                messages: [
                    {
                        role: 'system',
                        content: 'You are a cybersecurity expert specializing in vulnerability remediation. Provide detailed, actionable remediation plans.'
                    },
                    {
                        role: 'user',
                        content: `Generate a detailed remediation plan for a ${vulnerability.severity} severity vulnerability of type ${vulnerability.type} found at endpoint ${vulnerability.endpoint}. Include immediate actions, technical steps, code examples, and best practices.`
                    }
                ],
                model: 'mixtral-8x7b-32768'
            });
            
            return chatCompletion.choices[0].message.content || generateFallbackRemediation(vulnerability);
        }
        
        return generateFallbackRemediation(vulnerability);
        
    } catch (error) {
        console.error('AI remediation generation failed:', error);
        return generateFallbackRemediation(vulnerability);
    }
}

function generateFallbackRemediation(vulnerability: Vulnerability): string {
    const severity = vulnerability.severity;
    const type = vulnerability.type;
    
    let remediation = `Remediation Plan for ${type} (${severity} Severity)

Priority: ${severity}
Timeframe: ${severity === 'CRITICAL' ? 'Immediate (0-24 hours)' : severity === 'HIGH' ? '1-3 days' : '1-7 days'}
Effort: ${severity === 'CRITICAL' ? 'High' : severity === 'HIGH' ? 'Medium-High' : 'Medium'}

Immediate Actions:
1. Assess the scope and impact of the vulnerability
2. Implement temporary mitigations if possible
3. Notify relevant stakeholders

Technical Remediation Steps:
1. Review the vulnerability details and affected code
2. Implement proper input validation and sanitization
3. Apply security patches or updates
4. Configure proper security headers
5. Implement proper authentication and authorization
6. Add comprehensive logging and monitoring

Best Practices:
1. Follow OWASP security guidelines
2. Implement defense in depth
3. Regular security testing and code reviews
4. Keep dependencies updated
5. Use security scanning tools in CI/CD

Testing Recommendations:
1. Verify the fix resolves the vulnerability
2. Test for regression issues
3. Perform security testing
4. Validate in staging environment before production

This remediation plan should be customized based on your specific environment and requirements.`;

    return remediation;
} 