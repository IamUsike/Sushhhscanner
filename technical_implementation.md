# API Risk Visualizer - Technical Implementation Guide

## Core Components to Build

### 1. API Scanner Engine (Backend)
```typescript
// Key modules needed:
// src/scanner/       # Contains core scanning logic
//  ├── endpointDiscovery.ts    // Discover all API endpoints
//  ├── authAnalyzer.ts        // Check authentication methods
//  ├── securityChecks.ts     // Run various security checks
//  └── riskCalculator.ts      // Calculate risk scores
// src/api/            # API routes and models for the backend service
//  ├── routes.ts
//  └── models.ts
// app.ts             # Main application entry point
```

**Priority Security Checks:**
- Missing authentication
- Weak/Basic auth usage
- No rate limiting
- Missing security headers (CORS, CSP, etc.)
- Exposed sensitive data
- SQL injection possibilities
- Broken access control

### 2. Risk Scoring Algorithm
```
Risk Score = (
    (Critical Issues × 40) +
    (High Issues × 20) +
    (Medium Issues × 10) +
    (Low Issues × 5)
) / Total Possible Points × 100
```

### 3. Visualization Components
- **Heatmap**: D3.js or Recharts for endpoint risk visualization
- **Dashboard**: React components for metrics
- **Timeline**: Show risk trends over multiple scans

## MVP Features for Hackathon

### Must Have (First 12 hours)
1. Basic API endpoint discovery
2. Simple authentication check
3. Risk score calculation
4. Basic web UI with results display

### Should Have (Next 6 hours)
1. Visual heatmap of risks
2. Downloadable report
3. 5+ security checks
4. Clean, modern UI

### Nice to Have (If time permits)
1. Real-time scanning progress
2. Historical comparison
3. API documentation parser
4. Export to JIRA/GitHub issues

## Quick Start Code Structure

```
api-risk-visualizer/
├── backend/
│   ├── src/
│   │   ├── scanner/
│   │   │   ├── endpointDiscovery.ts
│   │   │   ├── authAnalyzer.ts
│   │   │   ├── securityChecks.ts
│   │   │   └── riskAnalysis.ts
│   │   ├── api/
│   │   │   ├── routes.ts
│   │   │   └── models.ts
│   │   └── app.ts
│   ├── package.json
│   └── tsconfig.json
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── RiskHeatmap.tsx
│   │   │   └── ReportGenerator.tsx
│   │   └── App.tsx
│   └── package.json
└── docker-compose.yml
```

## Security Checks Implementation

### 1. Authentication Check
```typescript
import axios from 'axios';

async function checkAuthentication(endpointUrl: string, headers?: Record<string, string>): Promise<{\n  risk: string;\n  issue: string;\n}> {\n  try {\n    // Test without auth\n    const responseNoAuth = await axios.get(endpointUrl, { validateStatus: () => true }); // Don't throw on non-2xx codes\n
    if (responseNoAuth.status === 200 || responseNoAuth.status === 302) { // Consider 302 for redirects to login\n      return { risk: 'CRITICAL', issue: 'No authentication required' };\n    }\n
    // Optionally test with weak/default auth here as well\n    // Example: const responseWithWeakAuth = await axios.get(endpointUrl, { headers: { 'Authorization': 'Basic YWRtaW46YWRtaW4=' } });\n
    // If you always expect some form of auth, and noAuth fails, then it's good.
    // More complex checks would involve valid token testing.
    return { risk: 'NONE', issue: 'Authentication seems required' };\n  } catch (error) {\n    console.error(`Error checking authentication for ${endpointUrl}:`, error.message);\n    return { risk: 'UNKNOWN', issue: 'Could not perform authentication check' };\n  }\n}
```

### 2. Rate Limiting Check
```typescript
import axios from 'axios';

async function checkRateLimiting(endpointUrl: string): Promise<{\n  risk: string;\n  issue: string;\n}> {\n  const requests = [];\n  for (let i = 0; i < 50; i++) { // Send 50 rapid requests\n    requests.push(axios.get(endpointUrl, { validateStatus: () => true }));\n  }\n
  const responses = await Promise.all(requests);\n
  const non2xxResponses = responses.filter(res => res.status !== 200 && res.status !== 302); // Look for 429, 403 etc.\n
  if (non2xxResponses.length < 5) { // If less than 5 requests failed, might indicate no rate limiting
    return { risk: 'HIGH', issue: 'No strong rate limiting detected' };\n  }\n
  return { risk: 'LOW', issue: 'Rate limiting appears to be in place' };\n}
```

### 3. Security Headers Check
```typescript
import { AxiosResponse } from 'axios';

function checkSecurityHeaders(response: AxiosResponse): { risk: string; missing_headers?: string[] } {\n  const criticalHeaders = [
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'Referrer-Policy' // Added common header
  ];\n
  const missing = criticalHeaders.filter(header => !response.headers[header.toLowerCase()]);\n
  if (missing.length > 0) {\n    return { risk: 'MEDIUM', missing_headers: missing };\n  }\n
  return { risk: 'NONE', issue: 'All critical security headers are present' };\n}
```

## API Endpoint Discovery Strategy

1. **Parse OpenAPI/Swagger docs** (if available)
2. **Common endpoint patterns**:
   - /api/v1/users
   - /api/v1/auth
   - /api/v1/admin
   - /api/v1/config
3. **HTTP method testing** (GET, POST, PUT, DELETE)
4. **Response analysis** for linked resources

## Visualization Tips

### Risk Heatmap (D3.js)
```javascript
const riskColors = {
    CRITICAL: '#d32f2f',
    HIGH: '#f57c00',
    MEDIUM: '#fbc02d',
    LOW: '#388e3c'
};

// Create heatmap cells for each endpoint
const cells = svg.selectAll('.cell')
    .data(endpoints)
    .enter().append('rect')
    .attr('fill', d => riskColors[d.risk_level]);
```

## Deployment for Demo

Use Docker for easy setup:
```dockerfile
# Backend
FROM node:18-alpine
WORKDIR /app/backend
COPY backend/package*.json ./
RUN npm install
COPY backend/ ./
RUN npm run build
CMD ["node", "dist/app.js"]
```