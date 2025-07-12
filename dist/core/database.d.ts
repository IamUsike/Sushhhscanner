import { User, Scan, Vulnerability } from '@/types';
declare class Database {
    private sqliteDb?;
    private pgClient?;
    private dbType;
    constructor();
    initialize(): Promise<void>;
    private initializeSQLite;
    private initializePostgreSQL;
    private createTables;
    private getUsersTableSQL;
    private getScansTableSQL;
    private getVulnerabilitiesTableSQL;
    private getReportsTableSQL;
    executeQuery(sql: string, params?: any[]): Promise<any>;
    private executeSQLiteQuery;
    private executePostgreSQLQuery;
    createUser(user: Omit<User, 'createdAt' | 'updatedAt'>): Promise<User>;
    getUserByEmail(email: string): Promise<User | null>;
    updateUserLastLogin(userId: string): Promise<void>;
    createScan(scan: Omit<Scan, 'createdAt' | 'updatedAt'>): Promise<Scan>;
    updateScan(scanId: string, updates: Partial<Scan>): Promise<void>;
    getScan(scanId: string): Promise<Scan | null>;
    getUserScans(userId: string, limit?: number): Promise<Scan[]>;
    createVulnerability(vulnerability: Vulnerability): Promise<void>;
    getScanVulnerabilities(scanId: string): Promise<Vulnerability[]>;
    close(): Promise<void>;
}
export declare const database: Database;
export {};
//# sourceMappingURL=database.d.ts.map