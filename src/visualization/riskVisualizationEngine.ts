import * as d3 from 'd3';
import { VulnerabilityData, RiskScore } from '../ai/riskScoringEngine';
import { RiskHeatmapData, MLInsight, RiskPortfolio } from '../ai/riskAnalyticsDashboard';
import { logger } from '../utils/logger';

export interface VisualizationConfig {
  container: string;
  width: number;
  height: number;
  margin: { top: number; right: number; bottom: number; left: number };
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

export class RiskVisualizationEngine {
  private config: VisualizationConfig;
  private svg: d3.Selection<SVGSVGElement, unknown, HTMLElement, any> | null = null;
  private tooltip: d3.Selection<HTMLDivElement, unknown, HTMLElement, any> | null = null;
  private colorScale: d3.ScaleLinear<string, string>;
  private sizeScale: d3.ScaleLinear<number, number>;
  
  // Animation and interaction state
  private animationDuration = 750;
  private zoomBehavior: d3.ZoomBehavior<Element, unknown> | null = null;
  private simulation: d3.Simulation<RiskMapNode, RiskMapLink> | null = null;

  constructor(config: VisualizationConfig) {
    this.config = config;
    
    // Initialize color scales for risk visualization
    this.colorScale = d3.scaleLinear<string>()
      .domain([0, 0.3, 0.6, 0.8, 1])
      .range(['#2ecc71', '#f1c40f', '#e67e22', '#e74c3c', '#8e44ad']);
    
    // Initialize size scale for node sizing
    this.sizeScale = d3.scaleLinear()
      .domain([0, 1])
      .range([8, 40]);
    
    this.initializeContainer();
  }

  private initializeContainer(): void {
    // Remove existing visualization
    d3.select(this.config.container).selectAll('*').remove();
    
    // Create main SVG container
    this.svg = d3.select(this.config.container)
      .append('svg')
      .attr('width', this.config.width)
      .attr('height', this.config.height)
      .attr('class', `risk-visualization ${this.config.theme}`);
    
    // Create tooltip container
    this.tooltip = d3.select('body')
      .append('div')
      .attr('class', 'risk-tooltip')
      .style('opacity', 0)
      .style('position', 'absolute')
      .style('pointer-events', 'none')
      .style('background', 'rgba(0, 0, 0, 0.8)')
      .style('color', 'white')
      .style('padding', '10px')
      .style('border-radius', '5px')
      .style('font-size', '12px')
      .style('z-index', '1000');

    // Initialize zoom behavior if interactive
    if (this.config.interactive) {
      this.zoomBehavior = d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.1, 10])
        .on('zoom', (event) => {
          this.svg?.selectAll('.zoomable')
            .attr('transform', event.transform);
        });
      
      this.svg.call(this.zoomBehavior);
    }

    logger.info('Risk visualization container initialized');
  }

  createRiskNetworkMap(riskData: RiskHeatmapData[]): void {
    logger.info('Creating interactive risk network map with D3.js...');

    const nodes: RiskMapNode[] = riskData.map((data, index) => ({
      id: `${data.endpoint}-${data.method}`,
      endpoint: data.endpoint,
      method: data.method,
      riskScore: data.riskScore,
      vulnerabilityCount: data.vulnerabilityCount,
      businessImpact: data.businessImpact,
      criticalityLevel: data.criticalityLevel
    }));

    // Generate links based on endpoint similarities and risk correlations
    const links: RiskMapLink[] = this.generateRiskLinks(nodes);

    // Set up force simulation
    this.simulation = d3.forceSimulation<RiskMapNode>(nodes)
      .force('link', d3.forceLink<RiskMapNode, RiskMapLink>(links)
        .id((d: any) => d.id)
        .distance(100)
        .strength(0.1))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(this.config.width / 2, this.config.height / 2))
      .force('collision', d3.forceCollide().radius((d: any) => this.sizeScale(d.riskScore) + 2));

    // Create zoomable group
    const g = this.svg!.append('g').attr('class', 'zoomable');

    // Create links
    const link = g.append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(links)
      .enter().append('line')
      .attr('stroke', '#999')
      .attr('stroke-opacity', 0.3)
      .attr('stroke-width', (d: RiskMapLink) => Math.sqrt(d.strength * 10));

    // Create nodes
    const node = g.append('g')
      .attr('class', 'nodes')
      .selectAll('circle')
      .data(nodes)
      .enter().append('circle')
      .attr('r', (d: RiskMapNode) => this.sizeScale(d.riskScore))
      .attr('fill', (d: RiskMapNode) => this.colorScale(d.riskScore))
      .attr('stroke', '#fff')
      .attr('stroke-width', 2)
      .style('cursor', 'pointer')
      .call(this.createDragBehavior());

    // Add node labels
    const labels = g.append('g')
      .attr('class', 'labels')
      .selectAll('text')
      .data(nodes)
      .enter().append('text')
      .text((d: RiskMapNode) => `${d.endpoint.split('/').pop()} (${d.method})`)
      .attr('text-anchor', 'middle')
      .attr('dy', '.35em')
      .attr('font-size', '10px')
      .attr('font-weight', 'bold')
      .attr('fill', this.config.theme === 'dark' ? '#fff' : '#000')
      .style('pointer-events', 'none');

    // Add interactivity
    node
      .on('mouseover', (event: any, d: RiskMapNode) => {
        this.showTooltip(event, d);
        // Highlight connected nodes
        node.style('opacity', (n: RiskMapNode) => 
          this.isConnected(d, n, links) ? 1 : 0.3);
        link.style('opacity', (l: RiskMapLink) => 
          l.source === d.id || l.target === d.id ? 0.8 : 0.1);
      })
      .on('mouseout', () => {
        this.hideTooltip();
        node.style('opacity', 1);
        link.style('opacity', 0.3);
      })
      .on('click', (event: any, d: RiskMapNode) => {
        this.onNodeClick(d);
      });

    // Update positions on simulation tick
    this.simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node
        .attr('cx', (d: RiskMapNode) => d.x!)
        .attr('cy', (d: RiskMapNode) => d.y!);

      labels
        .attr('x', (d: RiskMapNode) => d.x!)
        .attr('y', (d: RiskMapNode) => d.y! + this.sizeScale(d.riskScore) + 15);
    });

    // Add legend
    this.createLegend();
    
    logger.info(`Risk network map created with ${nodes.length} nodes and ${links.length} links`);
  }

  createRiskHeatmap(riskData: RiskHeatmapData[]): void {
    logger.info('Creating risk heatmap visualization...');

    const margin = this.config.margin;
    const width = this.config.width - margin.left - margin.right;
    const height = this.config.height - margin.top - margin.bottom;

    // Clear previous content
    this.svg!.selectAll('*').remove();

    const g = this.svg!.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Prepare data matrix
    const methods = Array.from(new Set(riskData.map(d => d.method)));
    const endpoints = Array.from(new Set(riskData.map(d => d.endpoint)));

    const xScale = d3.scaleBand()
      .domain(methods)
      .range([0, width])
      .padding(0.1);

    const yScale = d3.scaleBand()
      .domain(endpoints)
      .range([0, height])
      .padding(0.1);

    // Create heatmap cells
    const cells = g.selectAll('.heatmap-cell')
      .data(riskData)
      .enter().append('rect')
      .attr('class', 'heatmap-cell')
      .attr('x', (d: RiskHeatmapData) => xScale(d.method)!)
      .attr('y', (d: RiskHeatmapData) => yScale(d.endpoint)!)
      .attr('width', xScale.bandwidth())
      .attr('height', yScale.bandwidth())
      .attr('fill', (d: RiskHeatmapData) => this.colorScale(d.riskScore))
      .attr('stroke', '#fff')
      .attr('stroke-width', 1)
      .style('cursor', 'pointer')
      .on('mouseover', (event: any, d: RiskHeatmapData) => {
        this.showHeatmapTooltip(event, d);
      })
      .on('mouseout', () => {
        this.hideTooltip();
      });

    // Add cell values
    g.selectAll('.heatmap-text')
      .data(riskData)
      .enter().append('text')
      .attr('class', 'heatmap-text')
      .attr('x', (d: RiskHeatmapData) => xScale(d.method)! + xScale.bandwidth() / 2)
      .attr('y', (d: RiskHeatmapData) => yScale(d.endpoint)! + yScale.bandwidth() / 2)
      .attr('text-anchor', 'middle')
      .attr('dy', '.35em')
      .attr('font-size', '10px')
      .attr('font-weight', 'bold')
      .attr('fill', (d: RiskHeatmapData) => d.riskScore > 0.5 ? '#fff' : '#000')
      .text((d: RiskHeatmapData) => `${(d.riskScore * 100).toFixed(0)}%`)
      .style('pointer-events', 'none');

    // Add axes
    g.append('g')
      .attr('class', 'x-axis')
      .attr('transform', `translate(0,${height})`)
      .call(d3.axisBottom(xScale))
      .selectAll('text')
      .style('fill', this.config.theme === 'dark' ? '#fff' : '#000');

    g.append('g')
      .attr('class', 'y-axis')
      .call(d3.axisLeft(yScale))
      .selectAll('text')
      .style('fill', this.config.theme === 'dark' ? '#fff' : '#000')
      .style('font-size', '10px');

    // Add color scale legend
    this.createColorScaleLegend();

    logger.info(`Heatmap created with ${riskData.length} data points`);
  }

  createRiskTimeline(timeSeriesData: TimeSeriesPoint[]): void {
    logger.info('Creating risk timeline visualization...');

    const margin = this.config.margin;
    const width = this.config.width - margin.left - margin.right;
    const height = this.config.height - margin.top - margin.bottom;

    this.svg!.selectAll('*').remove();

    const g = this.svg!.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Set up scales
    const xScale = d3.scaleTime()
      .domain(d3.extent(timeSeriesData, (d: TimeSeriesPoint) => d.timestamp) as [Date, Date])
      .range([0, width]);

    const yScale = d3.scaleLinear()
      .domain([0, d3.max(timeSeriesData, (d: TimeSeriesPoint) => d.value)!])
      .range([height, 0]);

    // Group data by category
    const categories = Array.from(new Set(timeSeriesData.map(d => d.category)));
    const colorCategories = d3.scaleOrdinal(d3.schemeCategory10).domain(categories);

    // Create line generator
    const line = d3.line<TimeSeriesPoint>()
      .x((d: TimeSeriesPoint) => xScale(d.timestamp))
      .y((d: TimeSeriesPoint) => yScale(d.value))
      .curve(d3.curveMonotoneX);

    // Draw lines for each category
    categories.forEach(category => {
      const categoryData = timeSeriesData.filter(d => d.category === category);
      
      g.append('path')
        .datum(categoryData)
        .attr('class', `timeline-line timeline-${category}`)
        .attr('fill', 'none')
        .attr('stroke', colorCategories(category))
        .attr('stroke-width', 2)
        .attr('d', line);

      // Add data points
      g.selectAll(`.timeline-point-${category}`)
        .data(categoryData)
        .enter().append('circle')
        .attr('class', `timeline-point timeline-point-${category}`)
        .attr('cx', (d: TimeSeriesPoint) => xScale(d.timestamp))
        .attr('cy', (d: TimeSeriesPoint) => yScale(d.value))
        .attr('r', 4)
        .attr('fill', colorCategories(category))
        .style('cursor', 'pointer')
        .on('mouseover', (event: any, d: TimeSeriesPoint) => {
          this.showTimelineTooltip(event, d);
        })
        .on('mouseout', () => {
          this.hideTooltip();
        });
    });

    // Add axes
    g.append('g')
      .attr('class', 'x-axis')
      .attr('transform', `translate(0,${height})`)
      .call(d3.axisBottom(xScale))
      .selectAll('text')
      .style('fill', this.config.theme === 'dark' ? '#fff' : '#000');

    g.append('g')
      .attr('class', 'y-axis')
      .call(d3.axisLeft(yScale))
      .selectAll('text')
      .style('fill', this.config.theme === 'dark' ? '#fff' : '#000');

    // Add legend
    this.createTimelineLegend(categories, colorCategories);

    logger.info(`Timeline created with ${timeSeriesData.length} data points across ${categories.length} categories`);
  }

  createMetricsDashboard(metrics: DashboardMetrics): void {
    logger.info('Creating metrics dashboard...');

    this.svg!.selectAll('*').remove();

    const cardWidth = 180;
    const cardHeight = 120;
    const padding = 20;
    const cols = Math.floor(this.config.width / (cardWidth + padding));

    const metricsData = [
      { label: 'Total Vulnerabilities', value: metrics.totalVulnerabilities, color: '#3498db', icon: '🔍' },
      { label: 'Critical Issues', value: metrics.criticalCount, color: '#e74c3c', icon: '🚨' },
      { label: 'High Priority', value: metrics.highCount, color: '#e67e22', icon: '⚠️' },
      { label: 'Medium Priority', value: metrics.mediumCount, color: '#f1c40f', icon: '📊' },
      { label: 'Low Priority', value: metrics.lowCount, color: '#2ecc71', icon: '✅' },
      { label: 'Avg Risk Score', value: `${(metrics.averageRiskScore * 100).toFixed(1)}%`, color: '#9b59b6', icon: '📈' },
      { label: 'Compliance Score', value: `${metrics.complianceScore}%`, color: '#1abc9c', icon: '🛡️' },
      { label: 'Trend', value: metrics.trendDirection, color: '#34495e', icon: metrics.trendDirection === 'up' ? '📈' : metrics.trendDirection === 'down' ? '📉' : '➡️' }
    ];

    const cards = this.svg!.selectAll('.metric-card')
      .data(metricsData)
      .enter().append('g')
      .attr('class', 'metric-card')
      .attr('transform', (d: any, i: number) => {
        const row = Math.floor(i / cols);
        const col = i % cols;
        const x = col * (cardWidth + padding) + padding;
        const y = row * (cardHeight + padding) + padding;
        return `translate(${x},${y})`;
      });

    // Card background
    cards.append('rect')
      .attr('width', cardWidth)
      .attr('height', cardHeight)
      .attr('rx', 10)
      .attr('ry', 10)
      .attr('fill', this.config.theme === 'dark' ? '#2c3e50' : '#ecf0f1')
      .attr('stroke', (d: any) => d.color)
      .attr('stroke-width', 2);

    // Card icon
    cards.append('text')
      .attr('x', cardWidth / 2)
      .attr('y', 30)
      .attr('text-anchor', 'middle')
      .attr('font-size', '24px')
      .text((d: any) => d.icon);

    // Card value
    cards.append('text')
      .attr('x', cardWidth / 2)
      .attr('y', 60)
      .attr('text-anchor', 'middle')
      .attr('font-size', '18px')
      .attr('font-weight', 'bold')
      .attr('fill', (d: any) => d.color)
      .text((d: any) => d.value);

    // Card label
    cards.append('text')
      .attr('x', cardWidth / 2)
      .attr('y', 85)
      .attr('text-anchor', 'middle')
      .attr('font-size', '12px')
      .attr('fill', this.config.theme === 'dark' ? '#bdc3c7' : '#7f8c8d')
      .text((d: any) => d.label);

    logger.info(`Metrics dashboard created with ${metricsData.length} metric cards`);
  }

  private generateRiskLinks(nodes: RiskMapNode[]): RiskMapLink[] {
    const links: RiskMapLink[] = [];
    
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const nodeA = nodes[i];
        const nodeB = nodes[j];
        
        // Create links based on endpoint similarity
        const endpointSimilarity = this.calculateEndpointSimilarity(nodeA.endpoint, nodeB.endpoint);
        if (endpointSimilarity > 0.3) {
          links.push({
            source: nodeA.id,
            target: nodeB.id,
            strength: endpointSimilarity,
            type: 'similar_risk'
          });
        }
        
        // Create links based on risk score proximity
        const riskDifference = Math.abs(nodeA.riskScore - nodeB.riskScore);
        if (riskDifference < 0.2) {
          links.push({
            source: nodeA.id,
            target: nodeB.id,
            strength: 1 - riskDifference,
            type: 'similar_risk'
          });
        }
      }
    }
    
    return links;
  }

  private calculateEndpointSimilarity(endpointA: string, endpointB: string): number {
    const pathsA = endpointA.split('/').filter(p => p);
    const pathsB = endpointB.split('/').filter(p => p);
    
    let commonParts = 0;
    const maxLength = Math.max(pathsA.length, pathsB.length);
    
    for (let i = 0; i < Math.min(pathsA.length, pathsB.length); i++) {
      if (pathsA[i] === pathsB[i]) {
        commonParts++;
      }
    }
    
    return commonParts / maxLength;
  }

  private createDragBehavior(): d3.DragBehavior<Element, RiskMapNode, any> {
    return d3.drag<Element, RiskMapNode>()
      .on('start', (event: any, d: RiskMapNode) => {
        if (!event.active) this.simulation?.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', (event: any, d: RiskMapNode) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', (event: any, d: RiskMapNode) => {
        if (!event.active) this.simulation?.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });
  }

  private isConnected(nodeA: RiskMapNode, nodeB: RiskMapNode, links: RiskMapLink[]): boolean {
    return nodeA.id === nodeB.id || links.some(link => 
      (link.source === nodeA.id && link.target === nodeB.id) ||
      (link.source === nodeB.id && link.target === nodeA.id)
    );
  }

  private showTooltip(event: any, data: RiskMapNode): void {
    this.tooltip!
      .style('opacity', 1)
      .html(`
        <strong>${data.endpoint}</strong><br/>
        Method: ${data.method}<br/>
        Risk Score: ${(data.riskScore * 100).toFixed(1)}%<br/>
        Vulnerabilities: ${data.vulnerabilityCount}<br/>
        Business Impact: ${(data.businessImpact * 100).toFixed(1)}%<br/>
        Criticality: ${data.criticalityLevel}
      `)
      .style('left', (event.pageX + 10) + 'px')
      .style('top', (event.pageY - 10) + 'px');
  }

  private showHeatmapTooltip(event: any, data: RiskHeatmapData): void {
    this.tooltip!
      .style('opacity', 1)
      .html(`
        <strong>${data.endpoint}</strong><br/>
        Method: ${data.method}<br/>
        Risk Score: ${(data.riskScore * 100).toFixed(1)}%<br/>
        Vulnerabilities: ${data.vulnerabilityCount}<br/>
        Criticality: ${data.criticalityLevel}
      `)
      .style('left', (event.pageX + 10) + 'px')
      .style('top', (event.pageY - 10) + 'px');
  }

  private showTimelineTooltip(event: any, data: TimeSeriesPoint): void {
    this.tooltip!
      .style('opacity', 1)
      .html(`
        <strong>${data.category}</strong><br/>
        Time: ${data.timestamp.toLocaleString()}<br/>
        Value: ${data.value}<br/>
        ${data.metadata ? `Details: ${JSON.stringify(data.metadata)}` : ''}
      `)
      .style('left', (event.pageX + 10) + 'px')
      .style('top', (event.pageY - 10) + 'px');
  }

  private hideTooltip(): void {
    this.tooltip!.style('opacity', 0);
  }

  private onNodeClick(node: RiskMapNode): void {
    logger.info(`Node clicked: ${node.endpoint} (${node.method})`);
    // Emit custom event for node selection
    const event = new CustomEvent('nodeSelected', { detail: node });
    document.dispatchEvent(event);
  }

  private createLegend(): void {
    const legend = this.svg!.append('g')
      .attr('class', 'legend')
      .attr('transform', `translate(${this.config.width - 150}, 20)`);

    const legendData = [
      { label: 'Critical (80-100%)', color: this.colorScale(0.9) },
      { label: 'High (60-80%)', color: this.colorScale(0.7) },
      { label: 'Medium (40-60%)', color: this.colorScale(0.5) },
      { label: 'Low (20-40%)', color: this.colorScale(0.3) },
      { label: 'Minimal (0-20%)', color: this.colorScale(0.1) }
    ];

    const legendItems = legend.selectAll('.legend-item')
      .data(legendData)
      .enter().append('g')
      .attr('class', 'legend-item')
      .attr('transform', (d: any, i: number) => `translate(0, ${i * 20})`);

    legendItems.append('circle')
      .attr('r', 8)
      .attr('fill', (d: any) => d.color);

    legendItems.append('text')
      .attr('x', 15)
      .attr('y', 4)
      .attr('font-size', '12px')
      .attr('fill', this.config.theme === 'dark' ? '#fff' : '#000')
      .text((d: any) => d.label);
  }

  private createColorScaleLegend(): void {
    const legendWidth = 200;
    const legendHeight = 20;
    
    const legend = this.svg!.append('g')
      .attr('class', 'color-legend')
      .attr('transform', `translate(${this.config.width - legendWidth - 50}, ${this.config.height - 60})`);

    // Create gradient
    const gradient = this.svg!.append('defs')
      .append('linearGradient')
      .attr('id', 'risk-gradient')
      .attr('x1', '0%')
      .attr('x2', '100%');

    gradient.selectAll('stop')
      .data([0, 0.25, 0.5, 0.75, 1])
      .enter().append('stop')
      .attr('offset', (d: number) => `${d * 100}%`)
      .attr('stop-color', (d: number) => this.colorScale(d));

    legend.append('rect')
      .attr('width', legendWidth)
      .attr('height', legendHeight)
      .style('fill', 'url(#risk-gradient)');

    legend.append('text')
      .attr('x', 0)
      .attr('y', -5)
      .attr('font-size', '12px')
      .attr('fill', this.config.theme === 'dark' ? '#fff' : '#000')
      .text('0%');

    legend.append('text')
      .attr('x', legendWidth)
      .attr('y', -5)
      .attr('text-anchor', 'end')
      .attr('font-size', '12px')
      .attr('fill', this.config.theme === 'dark' ? '#fff' : '#000')
      .text('100%');
  }

  private createTimelineLegend(categories: string[], colorScale: d3.ScaleOrdinal<string, string>): void {
    const legend = this.svg!.append('g')
      .attr('class', 'timeline-legend')
      .attr('transform', `translate(${this.config.width - 150}, 20)`);

    const legendItems = legend.selectAll('.legend-item')
      .data(categories)
      .enter().append('g')
      .attr('class', 'legend-item')
      .attr('transform', (d: string, i: number) => `translate(0, ${i * 20})`);

    legendItems.append('line')
      .attr('x1', 0)
      .attr('x2', 15)
      .attr('y1', 0)
      .attr('y2', 0)
      .attr('stroke', colorScale)
      .attr('stroke-width', 3);

    legendItems.append('text')
      .attr('x', 20)
      .attr('y', 4)
      .attr('font-size', '12px')
      .attr('fill', this.config.theme === 'dark' ? '#fff' : '#000')
      .text((d: string) => d);
  }

  updateVisualization(newData: any): void {
    logger.info('Updating visualization with new data...');
    
    if (this.config.realTime) {
      // Implement smooth transitions for real-time updates
      this.svg!.selectAll('*')
        .transition()
        .duration(this.animationDuration)
        .ease(d3.easeLinear);
    }
  }

  exportVisualization(format: 'svg' | 'png'): string {
    if (format === 'svg') {
      return new XMLSerializer().serializeToString(this.svg!.node()!);
    } else {
      // For PNG, would need additional canvas conversion
      logger.warn('PNG export not implemented yet');
      return '';
    }
  }

  destroy(): void {
    if (this.simulation) {
      this.simulation.stop();
    }
    if (this.tooltip) {
      this.tooltip.remove();
    }
    if (this.svg) {
      this.svg.selectAll('*').remove();
    }
    logger.info('Visualization engine destroyed');
  }
} 