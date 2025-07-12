import { RiskHeatmapData } from '../ai/riskAnalyticsDashboard';
export interface VisualizationConfig {
    container: string;
    width: number;
    height: number;
    margin: {
        top: number;
        right: number;
        bottom: number;
        left: number;
    };
    theme: 'light' | 'dark';
    interactive: boolean;
    realTime: boolean;
}
export interface RiskMapNode {
    id: string;
    endpoint: string;
    method: string;
    riskScore: number;
    vulnerabilityCount: number;
    businessImpact: number;
    criticalityLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    x?: number;
    y?: number;
    fx?: number | null;
    fy?: number | null;
    radius?: number;
    color?: string;
}
export interface RiskMapLink {
    source: string;
    target: string;
    strength: number;
    type: 'dependency' | 'data_flow' | 'similar_risk';
}
export interface TimeSeriesPoint {
    timestamp: Date;
    value: number;
    category: string;
    metadata?: any;
}
export interface DashboardMetrics {
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    averageRiskScore: number;
    complianceScore: number;
    trendDirection: 'up' | 'down' | 'stable';
}
export declare class RiskVisualizationEngine {
    private config;
    private svg;
    private tooltip;
    private colorScale;
    private sizeScale;
    private animationDuration;
    private zoomBehavior;
    private simulation;
    constructor(config: VisualizationConfig);
    private initializeContainer;
    createRiskNetworkMap(riskData: RiskHeatmapData[]): void;
    createRiskHeatmap(riskData: RiskHeatmapData[]): void;
    createRiskTimeline(timeSeriesData: TimeSeriesPoint[]): void;
    createMetricsDashboard(metrics: DashboardMetrics): void;
    private generateRiskLinks;
    private calculateEndpointSimilarity;
    private createDragBehavior;
    private isConnected;
    private showTooltip;
    private showHeatmapTooltip;
    private showTimelineTooltip;
    private hideTooltip;
    private onNodeClick;
    private createLegend;
    private createColorScaleLegend;
    private createTimelineLegend;
    updateVisualization(newData: any): void;
    exportVisualization(format: 'svg' | 'png'): string;
    destroy(): void;
}
//# sourceMappingURL=riskVisualizationEngine.d.ts.map