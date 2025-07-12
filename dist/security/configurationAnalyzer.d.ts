import { MisconfigurationResult } from './misconfigurationDetector';
export interface ConfigurationFile {
    filename: string;
    content: string;
    type: 'json' | 'yaml' | 'xml' | 'ini' | 'env' | 'unknown';
    url?: string;
}
export interface APIConfiguration {
    endpoints: Array<{
        path: string;
        method: string;
        authentication?: any;
        parameters?: any;
    }>;
    security?: any;
    swagger?: any;
}
export declare class ConfigurationAnalyzer {
    private readonly dangerousDbPatterns;
    private readonly weakCredentials;
    private readonly dangerousConfigs;
    analyzeConfiguration(configFile: ConfigurationFile): Promise<MisconfigurationResult[]>;
    analyzeAPIConfiguration(apiConfig: APIConfiguration, baseUrl: string): Promise<MisconfigurationResult[]>;
    private parseConfiguration;
    private checkExposedCredentials;
    private checkDangerousConfigurations;
    private checkWeakCredentials;
    private analyzeJSONConfiguration;
    private analyzeYAMLConfiguration;
    private analyzeEnvConfiguration;
    private analyzeSwaggerSecurity;
    private extractMatchingLine;
}
//# sourceMappingURL=configurationAnalyzer.d.ts.map