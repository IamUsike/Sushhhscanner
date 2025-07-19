import { Vulnerability, RemediationGuidance } from '../types';
export declare class RecommendationService {
    constructor();
    /**
     * Generates actionable remediation guidance for a given vulnerability.
     * @param vulnerability The detected vulnerability.
     * @returns RemediationGuidance object.
     */
    generateRecommendation(vulnerability: Vulnerability): RemediationGuidance;
    private getPriorityBySeverity;
}
//# sourceMappingURL=RecommendationService.d.ts.map