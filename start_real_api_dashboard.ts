import { RiskScoringEngine } from './src/ai/riskScoringEngine';
import { DashboardServer, DashboardConfig } from './src/visualization/dashboardServer';

async function startRealApiDashboard() {
    console.log('\n🚀 Starting Real API Dashboard Server...\n');

    try {
        // Initialize AI/ML Risk Scoring Engine
        console.log('⏳ Initializing AI/ML Risk Scoring Engine...');
        const riskEngine = new RiskScoringEngine();
        await riskEngine.initialize();
        console.log('✅ AI/ML Risk Scoring Engine ready!');

        // Configure dashboard server
        const dashboardConfig: DashboardConfig = {
            port: 3000,
            host: 'localhost',
            corsOrigins: ['http://localhost:3000', 'http://127.0.0.1:3000'],
            updateInterval: 5000
        };

        // Initialize and start dashboard server
        console.log('⏳ Starting dashboard server...');
        const dashboardServer = new DashboardServer(dashboardConfig, riskEngine);
        await dashboardServer.start();
        
        console.log('\n🎉 Real API Dashboard Server Successfully Started!');
        console.log('=' .repeat(60));
        console.log('\n📍 Available Pages:');
        console.log(`  🌐 Main Dashboard: http://localhost:3000/`);
        console.log(`  🔧 Real API Dashboard: http://localhost:3000/real_api_dashboard.html`);
        console.log(`  📊 Regular Dashboard: http://localhost:3000/dashboard.html`);
        
        console.log('\n🚀 API Endpoints:');
        console.log('  📈 GET /api/health - Server health status');
        console.log('  🎯 POST /api/scan/start - Start real-time API scan');
        console.log('  📊 GET /api/scan/status/:scanId - Get scan status');
        console.log('  📋 GET /api/risk/metrics - Dashboard metrics');
        console.log('  🤖 GET /api/risk/insights - AI security insights');

        console.log('\n✅ Real API Dashboard is ready for use!');
        console.log('🌐 Open http://localhost:3000/real_api_dashboard.html in your browser');
        console.log('\n💡 Press Ctrl+C to stop the server');

        // Keep the process alive
        process.on('SIGINT', async () => {
            console.log('\n\n🛑 Shutting down Real API Dashboard...');
            await dashboardServer.stop();
            console.log('✅ Server stopped gracefully');
            process.exit(0);
        });

        // Keep alive
        await new Promise(() => {});

    } catch (error: any) {
        console.error(`\n❌ Failed to start Real API Dashboard: ${error.message}`);
        console.error(error.stack);
        process.exit(1);
    }
}

// Start the Real API Dashboard
startRealApiDashboard().catch(console.error); 