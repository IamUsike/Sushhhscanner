import { EndpointInfo, ScanTarget } from '../types';
import { DiscoveryOptions } from './endpointDiscovery';
export declare class SwaggerDiscovery {
    private target;
    private options;
    private commonSwaggerPaths;
    constructor(target: ScanTarget, options: DiscoveryOptions);
    discover(): Promise<EndpointInfo[]>;
    private parseSwaggerFromUrl;
    private parseSwaggerSpec;
    private createEndpointFromOperation;
    private parseSwaggerParameters;
    private mapSwaggerParameterType;
    private mapSwaggerDataType;
    private parseSwaggerAuthentication;
    private parseSwaggerResponseTypes;
    private discoverSwaggerUrlsFromHtml;
    private deduplicateEndpoints;
}
//# sourceMappingURL=swaggerDiscovery.d.ts.map