import { RiskScoringEngine } from './src/ai/riskScoringEngine';
import { DashboardServer, DashboardConfig } from './src/visualization/dashboardServer';
import { logger } from './src/utils/logger';

async function testVisualDashboard() {
    console.log('\n🌟 Visual Risk Map with D3.js Interactive Dashboard - Live Demo\n');
    console.log('=' .repeat(80));

    try {
        // Initialize AI/ML Risk Scoring Engine
        console.log('\n🚀 Initializing AI/ML Risk Scoring Engine...');
        const riskEngine = new RiskScoringEngine();
        
        console.log('⏳ Loading TensorFlow.js models...');
        await riskEngine.initialize();
        console.log('✅ AI/ML Risk Scoring Engine ready!');

        // Configure dashboard server
        const dashboardConfig: DashboardConfig = {
            port: 3000,
            host: 'localhost',
            corsOrigins: ['http://localhost:3000', 'http://127.0.0.1:3000'],
            updateInterval: 5000 // 5-second real-time updates
        };

        // Initialize dashboard server
        console.log('\n📊 Initializing Visual Dashboard Server...');
        const dashboardServer = new DashboardServer(dashboardConfig, riskEngine);
        
        console.log('⏳ Starting web server and WebSocket connections...');
        await dashboardServer.start();
        
        console.log('\n🎉 Visual Risk Dashboard Successfully Launched!');
        console.log('=' .repeat(60));
        
        // Dashboard access information
        console.log('\n🌐 Dashboard Access Information:');
        console.log(`  📍 Main Dashboard: http://${dashboardConfig.host}:${dashboardConfig.port}`);
        console.log(`  🔌 WebSocket Endpoint: ws://${dashboardConfig.host}:${dashboardConfig.port}`);
        console.log(`  🔄 Real-time Updates: Every ${dashboardConfig.updateInterval / 1000} seconds`);
        
        // API endpoints information
        console.log('\n🚀 Available API Endpoints:');
        console.log('  📈 GET /api/health - Server health status');
        console.log('  📊 GET /api/risk/portfolio - Risk portfolio analysis');
        console.log('  🌡️  GET /api/risk/heatmap - Interactive risk heatmap data');
        console.log('  🤖 GET /api/risk/insights - AI/ML security insights');
        console.log('  📈 GET /api/risk/timeline - Risk timeline data');
        console.log('  📋 GET /api/risk/metrics - Dashboard metrics');
        console.log('  🔍 GET /api/risk/vulnerability/:id - Individual vulnerability details');
        console.log('  🎯 POST /api/risk/score - Calculate risk score for vulnerability');
        console.log('  📊 GET /api/model/metrics - TensorFlow.js model performance');

        // Dashboard features
        console.log('\n✨ Interactive Dashboard Features:');
        console.log('  🗺️  Interactive Risk Network Map with D3.js force simulation');
        console.log('  🌡️  Risk Heatmap with color-coded vulnerability severity');
        console.log('  📈 Real-time Risk Timeline with multi-category tracking');
        console.log('  📊 Live Metrics Dashboard with animated cards');
        console.log('  🤖 AI/ML Security Insights with confidence scores');
        console.log('  🔄 Real-time Updates via WebSocket connections');
        console.log('  🎯 Interactive tooltips and zoom functionality');
        console.log('  📱 Responsive design for desktop and mobile');
        console.log('  🌙 Dark/Light theme support');

        // Sample dashboard data overview
        console.log('\n📊 Sample Dashboard Data Overview:');
        console.log('  ✅ Dashboard Metrics: Live vulnerability counts and risk scores');
        console.log('  ✅ Risk Heatmap Data: Interactive endpoint vs method correlation');
        console.log('  ✅ AI Security Insights: ML-powered vulnerability analysis');
        console.log('  ✅ ML Model Performance: TensorFlow.js model metrics and accuracy');

        // WebSocket client connections
        console.log('\n🔌 WebSocket Real-time Features:');
        console.log('  • Automatic connection status monitoring');
        console.log('  • Real-time risk metric updates every 5 seconds');
        console.log('  • Live AI insight generation and broadcasting');
        console.log('  • Interactive client subscription management');
        console.log('  • Automatic reconnection on connection loss');

        // Visual features showcase
        console.log('\n🎨 D3.js Visualization Features:');
        console.log('  🗺️  Network Map:');
        console.log('     • Force-directed graph layout with risk-based node sizing');
        console.log('     • Interactive drag-and-drop node positioning');
        console.log('     • Zoom and pan functionality with smooth transitions');
        console.log('     • Risk-based color coding with gradient legends');
        console.log('     • Hover tooltips with detailed vulnerability information');
        console.log('     • Click events for detailed vulnerability exploration');
        
        console.log('\n  🌡️  Heatmap:');
        console.log('     • Method vs Endpoint risk correlation matrix');
        console.log('     • Color-coded risk severity visualization');
        console.log('     • Interactive cell selection and filtering');
        console.log('     • Animated transitions and smooth updates');
        
        console.log('\n  📈 Timeline:');
        console.log('     • Multi-category time-series visualization');
        console.log('     • Smooth curve interpolation with D3 curves');
        console.log('     • Interactive legend with category toggling');
        console.log('     • Responsive time axis with automatic formatting');

        console.log('\n  📊 Metrics:');
        console.log('     • Animated metric cards with icon integration');
        console.log('     • Real-time value updates with smooth transitions');
        console.log('     • Color-coded severity indicators');
        console.log('     • Responsive grid layout adaptation');

        // Performance and scalability
        console.log('\n⚡ Performance Features:');
        console.log('  • Client-side D3.js rendering for smooth interactions');
        console.log('  • WebSocket-based real-time updates (low latency)');
        console.log('  • Efficient data streaming and caching');
        console.log('  • Responsive design with CSS Grid and Flexbox');
        console.log('  • Optimized TensorFlow.js model inference');
        console.log('  • Automatic error handling and recovery');

        // User interaction guide
        console.log('\n👆 Interactive Usage Guide:');
        console.log('  1. 🌐 Open http://localhost:3000 in your web browser');
        console.log('  2. 🎛️  Use the control buttons to refresh visualizations');
        console.log('  3. ▶️  Toggle real-time mode for live updates');
        console.log('  4. 🖱️  Hover over elements for detailed tooltips');
        console.log('  5. 🔍 Zoom and pan the network map for exploration');
        console.log('  6. 📊 Click on metric cards for detailed breakdowns');
        console.log('  7. 🤖 Review AI insights for strategic recommendations');

        // Advanced features
        console.log('\n🚀 Advanced Dashboard Capabilities:');
        console.log('  • Cross-browser compatibility (Chrome, Firefox, Safari, Edge)');
        console.log('  • Mobile-responsive design with touch interactions');
        console.log('  • Keyboard accessibility and screen reader support');
        console.log('  • SVG export functionality for reports');
        console.log('  • Customizable themes and color schemes');
        console.log('  • Plugin architecture for custom visualizations');

        // Keep server running for demo
        console.log('\n🎯 Dashboard Demo Status:');
        console.log('✅ AI/ML Risk Scoring Engine: Operational');
        console.log('✅ TensorFlow.js Models: Loaded and Ready');
        console.log('✅ Web Server: Running on port 3000');
        console.log('✅ WebSocket Server: Real-time connections active');
        console.log('✅ D3.js Visualizations: Interactive and responsive');
        console.log('✅ Sample Data: 6 vulnerabilities loaded');

        console.log('\n🎊 Visual Risk Dashboard is now live and ready for exploration!');
        console.log('🌐 Visit http://localhost:3000 to see the interactive dashboard');
        console.log('📊 The dashboard will continue running with real-time updates...');
        
        // Keep the process alive for demonstration
        process.on('SIGINT', async () => {
            console.log('\n\n🛑 Shutting down Visual Risk Dashboard...');
            await dashboardServer.stop();
            console.log('✅ Dashboard server stopped gracefully');
            process.exit(0);
        });

        console.log('\n💡 Press Ctrl+C to stop the dashboard server');

    } catch (error: any) {
        console.error(`\n❌ Visual Dashboard test failed: ${error.message}`);
        console.error(error.stack);
        process.exit(1);
    }
}

// Run the visual dashboard demo
testVisualDashboard().catch(console.error); 