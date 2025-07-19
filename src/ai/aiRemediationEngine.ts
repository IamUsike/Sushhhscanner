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
                console.warn('No Gemini API key found, using fallback remediation');
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

Please provide a concise remediation plan with exactly 3-4 key steps. Format your response as plain text without any markdown formatting, bullet points, or special characters. Use simple numbered lists and clear, actionable language.

Structure your response as:
1. Immediate Action (what to do within 1 hour)
2. Technical Fix (specific code or configuration changes)
3. Security Enhancement (additional security measures)
4. Verification Step (how to test the fix)

Keep each step concise and practical. Do not use markdown formatting, asterisks, or special characters.`;

            const result = await model.generateContent(prompt);
            const response = result.response;
            const text = response.text();
            
            if (text && text.trim()) {
                return text.trim();
            } else {
                console.warn('Empty response from Gemini, using fallback');
                return generateFallbackRemediation(vulnerability);
            }
            
        } else if (provider === 'groq') {
            const apiKey = process.env.GROQ_API_KEY;
            if (!apiKey) {
                console.warn('No Groq API key found, using fallback remediation');
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
            
            const content = chatCompletion.choices[0].message.content;
            if (content && content.trim()) {
                return content.trim();
            } else {
                console.warn('Empty response from Groq, using fallback');
                return generateFallbackRemediation(vulnerability);
            }
        }
        
        console.warn('No valid LLM provider configured, using fallback');
        return generateFallbackRemediation(vulnerability);
        
    } catch (error) {
        console.error('AI remediation generation failed:', error);
        console.log('Using fallback remediation for vulnerability:', vulnerability.type);
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