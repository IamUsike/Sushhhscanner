import { Router } from 'express';
import Joi from 'joi';
import { authenticate, validateRequest, asyncHandler } from '@utils/middleware';
import { logger, logAIAnalysis } from '@utils/logger';
import { AIAnalysisRequest, AIAnalysisResponse, APIResponse } from '@/types';

const router = Router();

// Validation schemas
const aiAnalysisSchema = Joi.object({
  type: Joi.string().valid('vulnerability_prediction', 'code_analysis', 'pattern_recognition', 'threat_modeling').required(),
  input: Joi.object({
    codeSnippet: Joi.string().when('type', {
      is: Joi.string().valid('code_analysis', 'vulnerability_prediction'),
      then: Joi.required(),
      otherwise: Joi.optional(),
    }),
    endpointPattern: Joi.string().when('type', {
      is: 'pattern_recognition',
      then: Joi.required(),
      otherwise: Joi.optional(),
    }),
    context: Joi.object().optional(),
  }).required(),
  modelConfig: Joi.object({
    provider: Joi.string().valid('huggingface', 'openai', 'tensorflow', 'local').optional(),
    modelName: Joi.string().optional(),
    confidenceThreshold: Joi.number().min(0).max(1).optional(),
    maxTokens: Joi.number().min(1).max(4000).optional(),
  }).optional(),
});

// POST /api/v1/ai/analyze - Perform AI analysis
router.post('/analyze',
  authenticate,
  validateRequest(aiAnalysisSchema),
  asyncHandler(async (req, res) => {
    const analysisRequest: AIAnalysisRequest = req.body;
    const startTime = Date.now();

    try {
      // Check if AI analysis is enabled
      const aiEnabled = process.env.AI_CONFIDENCE_THRESHOLD && 
        (process.env.OPENAI_API_KEY || process.env.HUGGINGFACE_API_KEY);

      if (!aiEnabled) {
        return res.status(503).json({
          success: false,
          error: {
            message: 'AI analysis is not configured or disabled',
            code: 'AI_NOT_AVAILABLE',
          },
          timestamp: new Date().toISOString(),
        } as APIResponse);
      }

      // Perform the analysis based on type
      let analysisResult: AIAnalysisResponse;

      switch (analysisRequest.type) {
        case 'vulnerability_prediction':
          analysisResult = await performVulnerabilityPrediction(analysisRequest);
          break;
        case 'code_analysis':
          analysisResult = await performCodeAnalysis(analysisRequest);
          break;
        case 'pattern_recognition':
          analysisResult = await performPatternRecognition(analysisRequest);
          break;
        case 'threat_modeling':
          analysisResult = await performThreatModeling(analysisRequest);
          break;
        default:
          return res.status(400).json({
            success: false,
            error: { message: 'Unsupported analysis type' },
            timestamp: new Date().toISOString(),
          } as APIResponse);
      }

      // Log the analysis
      logAIAnalysis(
        analysisRequest.type,
        analysisRequest.input,
        analysisResult.prediction,
        {
          processingTime: Date.now() - startTime,
          confidence: analysisResult.prediction.confidence,
        }
      );

      const response: APIResponse<AIAnalysisResponse> = {
        success: true,
        data: analysisResult,
        metadata: {
          timestamp: new Date(),
          requestId: analysisResult.metadata.requestId,
        },
      };

      res.json(response);
    } catch (error) {
      logger.error('AI analysis failed:', error);

      res.status(500).json({
        success: false,
        error: {
          message: 'AI analysis failed',
          details: error instanceof Error ? error.message : 'Unknown error',
        },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }
  })
);

// GET /api/v1/ai/models - Get available AI models
router.get('/models',
  authenticate,
  asyncHandler(async (req, res) => {
    const availableModels = [
      {
        provider: 'huggingface',
        modelName: 'mrm8488/codebert-base-finetuned-detect-insecure-code',
        description: 'CodeBERT fine-tuned for insecure code detection',
        capabilities: ['vulnerability_prediction', 'code_analysis'],
        accuracy: 0.653,
        enabled: !!process.env.HUGGINGFACE_API_KEY,
      },
      {
        provider: 'openai',
        modelName: 'gpt-3.5-turbo',
        description: 'OpenAI GPT-3.5 for general code analysis',
        capabilities: ['code_analysis', 'threat_modeling', 'pattern_recognition'],
        accuracy: 0.8,
        enabled: !!process.env.OPENAI_API_KEY,
      },
      {
        provider: 'tensorflow',
        modelName: 'local-vulnerability-classifier',
        description: 'Local TensorFlow.js model for vulnerability classification',
        capabilities: ['vulnerability_prediction'],
        accuracy: 0.7,
        enabled: false, // Not implemented yet
      },
    ];

    const response: APIResponse<typeof availableModels> = {
      success: true,
      data: availableModels,
      metadata: {
        timestamp: new Date(),
      },
    };

    res.json(response);
  })
);

// GET /api/v1/ai/health - Check AI service health
router.get('/health',
  authenticate,
  asyncHandler(async (req, res) => {
    const healthStatus = {
      status: 'healthy',
      services: {
        huggingface: {
          available: !!process.env.HUGGINGFACE_API_KEY,
          status: process.env.HUGGINGFACE_API_KEY ? 'active' : 'not_configured',
        },
        openai: {
          available: !!process.env.OPENAI_API_KEY,
          status: process.env.OPENAI_API_KEY ? 'active' : 'not_configured',
        },
        tensorflow: {
          available: false,
          status: 'not_implemented',
        },
      },
      confidenceThreshold: parseFloat(process.env.AI_CONFIDENCE_THRESHOLD || '0.7'),
      lastCheck: new Date(),
    };

    const response: APIResponse<typeof healthStatus> = {
      success: true,
      data: healthStatus,
      metadata: {
        timestamp: new Date(),
      },
    };

    res.json(response);
  })
);

// Helper functions for different types of AI analysis

async function performVulnerabilityPrediction(request: AIAnalysisRequest): Promise<AIAnalysisResponse> {
  const { codeSnippet, context } = request.input;
  
  // Simulate vulnerability prediction (replace with actual ML model)
  const vulnerabilityPatterns = [
    { pattern: /eval\s*\(/, type: 'COMMAND_INJECTION', severity: 'CRITICAL', confidence: 0.95 },
    { pattern: /SELECT.*FROM.*WHERE.*=.*\+/, type: 'SQL_INJECTION', severity: 'CRITICAL', confidence: 0.9 },
    { pattern: /innerHTML\s*=/, type: 'XSS', severity: 'HIGH', confidence: 0.8 },
    { pattern: /document\.write\s*\(/, type: 'XSS', severity: 'HIGH', confidence: 0.85 },
    { pattern: /password\s*=\s*["'].*["']/, type: 'SENSITIVE_DATA_EXPOSURE', severity: 'HIGH', confidence: 0.7 },
  ];

  let bestMatch = null;
  let maxConfidence = 0;

  for (const pattern of vulnerabilityPatterns) {
    if (codeSnippet && pattern.pattern.test(codeSnippet)) {
      if (pattern.confidence > maxConfidence) {
        maxConfidence = pattern.confidence;
        bestMatch = pattern;
      }
    }
  }

  const isVulnerable = bestMatch !== null;
  const confidence = isVulnerable ? maxConfidence : 0.1;

  return {
    prediction: {
      vulnerable: isVulnerable,
      confidence,
      vulnerabilityType: bestMatch?.type as any,
      severity: bestMatch?.severity as any,
      explanation: isVulnerable 
        ? `Detected ${bestMatch?.type} pattern with ${Math.round(confidence * 100)}% confidence`
        : 'No clear vulnerability patterns detected',
      cwe: getCWEForVulnerability(bestMatch?.type),
      remediation: getRemediationForVulnerability(bestMatch?.type),
    },
    performance: {
      processingTime: Math.random() * 1000 + 200, // Simulate processing time
      modelVersion: 'pattern-matcher-v1.0',
    },
    metadata: {
      timestamp: new Date(),
      requestId: generateRequestId(),
    },
  };
}

async function performCodeAnalysis(request: AIAnalysisRequest): Promise<AIAnalysisResponse> {
  const { codeSnippet, context } = request.input;
  
  // Simple code quality analysis
  const issues = [];
  let overallRisk = false;
  let confidence = 0.6;

  if (codeSnippet) {
    // Check for common code quality issues
    if (/var\s+/.test(codeSnippet)) {
      issues.push('Use of var instead of let/const');
    }
    if (/==\s/.test(codeSnippet)) {
      issues.push('Use of loose equality operator');
    }
    if (/console\.log/.test(codeSnippet)) {
      issues.push('Console logging detected (potential information disclosure)');
    }
    if (!/^\s*\/\//.test(codeSnippet) && codeSnippet.length > 200) {
      issues.push('Large code block without comments');
    }

    overallRisk = issues.length > 2;
    confidence = Math.min(0.9, 0.5 + (issues.length * 0.1));
  }

  return {
    prediction: {
      vulnerable: overallRisk,
      confidence,
      explanation: issues.length > 0 
        ? `Code quality issues found: ${issues.join(', ')}`
        : 'Code appears to follow good practices',
      remediation: issues.length > 0 
        ? 'Address the identified code quality issues to improve security and maintainability'
        : undefined,
    },
    performance: {
      processingTime: Math.random() * 500 + 100,
      modelVersion: 'code-analyzer-v1.0',
    },
    metadata: {
      timestamp: new Date(),
      requestId: generateRequestId(),
    },
  };
}

async function performPatternRecognition(request: AIAnalysisRequest): Promise<AIAnalysisResponse> {
  const { endpointPattern, context } = request.input;
  
  // Analyze endpoint patterns for security risks
  let vulnerable = false;
  let confidence = 0.5;
  let explanation = 'Standard endpoint pattern';

  if (endpointPattern) {
    // Check for risky endpoint patterns
    if (/\/admin|\/debug|\/config/.test(endpointPattern)) {
      vulnerable = true;
      confidence = 0.9;
      explanation = 'Administrative endpoint detected - ensure proper access controls';
    } else if (/\/api\/v\d+\/.*\/\d+$/.test(endpointPattern)) {
      vulnerable = true;
      confidence = 0.7;
      explanation = 'Direct ID access pattern - check for broken object level authorization';
    } else if (/\.(json|xml|txt|log)$/.test(endpointPattern)) {
      vulnerable = true;
      confidence = 0.8;
      explanation = 'File access endpoint - verify authorization and path traversal protection';
    }
  }

  return {
    prediction: {
      vulnerable,
      confidence,
      explanation,
      remediation: vulnerable 
        ? 'Implement proper authentication and authorization for sensitive endpoints'
        : undefined,
    },
    performance: {
      processingTime: Math.random() * 300 + 50,
      modelVersion: 'pattern-recognizer-v1.0',
    },
    metadata: {
      timestamp: new Date(),
      requestId: generateRequestId(),
    },
  };
}

async function performThreatModeling(request: AIAnalysisRequest): Promise<AIAnalysisResponse> {
  const { context } = request.input;
  
  // Basic threat modeling based on context
  const threats = [];
  let riskLevel = 'LOW';
  
  if (context) {
    if (context.hasAuthentication === false) {
      threats.push('Unauthenticated access');
      riskLevel = 'HIGH';
    }
    if (context.exposesData === true) {
      threats.push('Data exposure');
      riskLevel = 'HIGH';
    }
    if (context.acceptsUserInput === true) {
      threats.push('Injection attacks');
      riskLevel = riskLevel === 'HIGH' ? 'CRITICAL' : 'MEDIUM';
    }
  }

  const vulnerable = threats.length > 0;
  const confidence = threats.length > 0 ? 0.8 : 0.3;

  return {
    prediction: {
      vulnerable,
      confidence,
      explanation: threats.length > 0 
        ? `Potential threats identified: ${threats.join(', ')}`
        : 'No obvious threat vectors identified',
      severity: riskLevel as any,
      remediation: threats.length > 0 
        ? 'Implement appropriate security controls for identified threat vectors'
        : undefined,
    },
    performance: {
      processingTime: Math.random() * 800 + 300,
      modelVersion: 'threat-modeler-v1.0',
    },
    metadata: {
      timestamp: new Date(),
      requestId: generateRequestId(),
    },
  };
}

// Helper functions
function getCWEForVulnerability(type?: string): string | undefined {
  const cweMap: Record<string, string> = {
    'SQL_INJECTION': 'CWE-89',
    'XSS': 'CWE-79',
    'COMMAND_INJECTION': 'CWE-78',
    'SENSITIVE_DATA_EXPOSURE': 'CWE-200',
  };
  
  return type ? cweMap[type] : undefined;
}

function getRemediationForVulnerability(type?: string): string | undefined {
  const remediationMap: Record<string, string> = {
    'SQL_INJECTION': 'Use parameterized queries and prepared statements',
    'XSS': 'Sanitize user input and use proper output encoding',
    'COMMAND_INJECTION': 'Avoid executing user input as commands, use safe APIs',
    'SENSITIVE_DATA_EXPOSURE': 'Remove hardcoded secrets and use environment variables',
  };
  
  return type ? remediationMap[type] : undefined;
}

function generateRequestId(): string {
  return 'ai-req-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
}

export { router as aiRoutes }; 