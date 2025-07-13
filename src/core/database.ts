import sqlite3 from 'sqlite3';
import { Client } from 'pg';
import path from 'path';
import fs from 'fs';
import { logger } from '@utils/logger';
import { User, Scan, Vulnerability, Report } from '@/types';

class Database {
  private sqliteDb?: sqlite3.Database;
  private pgClient?: Client;
  private dbType: 'sqlite' | 'postgresql';

  constructor() {
    this.dbType = (process.env.DATABASE_TYPE as 'sqlite' | 'postgresql') || 'sqlite';
  }

  async initialize(): Promise<void> {
    try {
      if (this.dbType === 'sqlite') {
        await this.initializeSQLite();
      } else {
        await this.initializePostgreSQL();
      }
      
      await this.createTables();
      logger.info(`Database initialized successfully (${this.dbType})`);
    } catch (error) {
      logger.error('Database initialization failed:', error);
      throw error;
    }
  }

  private async initializeSQLite(): Promise<void> {
    const dbPath = process.env.DATABASE_PATH || './data/security_scans.db';
    const dbDir = path.dirname(dbPath);

    // Ensure data directory exists
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }

    return new Promise((resolve, reject) => {
      this.sqliteDb = new sqlite3.Database(dbPath, (err) => {
        if (err) {
          reject(err);
        } else {
          logger.info(`SQLite database connected: ${dbPath}`);
          resolve();
        }
      });
    });
  }

  private async initializePostgreSQL(): Promise<void> {
    const connectionString = process.env.DATABASE_URL;
    
    if (!connectionString) {
      throw new Error('DATABASE_URL is required for PostgreSQL');
    }

    this.pgClient = new Client({ connectionString });
    await this.pgClient.connect();
    logger.info('PostgreSQL database connected');
  }

  private async createTables(): Promise<void> {
    const tables = [
      this.getUsersTableSQL(),
      this.getScansTableSQL(),
      this.getVulnerabilitiesTableSQL(),
      this.getReportsTableSQL(),
    ];

    for (const sql of tables) {
      await this.executeQuery(sql);
    }
  }

  private getUsersTableSQL(): string {
    if (this.dbType === 'sqlite') {
      return `
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_login_at DATETIME
        )
      `;
    } else {
      return `
        CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role VARCHAR(50) NOT NULL DEFAULT 'user',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          last_login_at TIMESTAMP
        )
      `;
    }
  }

  private getScansTableSQL(): string {
    if (this.dbType === 'sqlite') {
      return `
        CREATE TABLE IF NOT EXISTS scans (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          target_config TEXT NOT NULL,
          scan_config TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          progress INTEGER DEFAULT 0,
          current_step TEXT,
          summary TEXT,
          metadata TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `;
    } else {
      return `
        CREATE TABLE IF NOT EXISTS scans (
          id UUID PRIMARY KEY,
          user_id UUID NOT NULL,
          target_config JSONB NOT NULL,
          scan_config JSONB NOT NULL,
          status VARCHAR(50) NOT NULL DEFAULT 'pending',
          progress INTEGER DEFAULT 0,
          current_step TEXT,
          summary JSONB,
          metadata JSONB NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `;
    }
  }

  private getVulnerabilitiesTableSQL(): string {
    if (this.dbType === 'sqlite') {
      return `
        CREATE TABLE IF NOT EXISTS vulnerabilities (
          id TEXT PRIMARY KEY,
          scan_id TEXT NOT NULL,
          type TEXT NOT NULL,
          severity TEXT NOT NULL,
          endpoint TEXT NOT NULL,
          method TEXT NOT NULL,
          parameter TEXT,
          payload TEXT,
          description TEXT NOT NULL,
          impact TEXT NOT NULL,
          confidence REAL NOT NULL,
          cwe TEXT,
          cvss REAL,
          evidence TEXT NOT NULL,
          ai_analysis TEXT,
          remediation TEXT NOT NULL,
          discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
      `;
    } else {
      return `
        CREATE TABLE IF NOT EXISTS vulnerabilities (
          id UUID PRIMARY KEY,
          scan_id UUID NOT NULL,
          type VARCHAR(100) NOT NULL,
          severity VARCHAR(20) NOT NULL,
          endpoint TEXT NOT NULL,
          method VARCHAR(10) NOT NULL,
          parameter TEXT,
          payload TEXT,
          description TEXT NOT NULL,
          impact TEXT NOT NULL,
          confidence DECIMAL(3,2) NOT NULL,
          cwe VARCHAR(20),
          cvss DECIMAL(3,1),
          evidence JSONB NOT NULL,
          ai_analysis JSONB,
          remediation JSONB NOT NULL,
          discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
      `;
    }
  }

  private getReportsTableSQL(): string {
    if (this.dbType === 'sqlite') {
      return `
        CREATE TABLE IF NOT EXISTS reports (
          id TEXT PRIMARY KEY,
          scan_id TEXT NOT NULL,
          type TEXT NOT NULL,
          format TEXT NOT NULL,
          template TEXT NOT NULL,
          sections TEXT NOT NULL,
          generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          download_url TEXT NOT NULL,
          expires_at DATETIME NOT NULL,
          size INTEGER NOT NULL,
          report_data TEXT NOT NULL, /* New column to store report content */
          FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
      `;
    } else {
      return `
        CREATE TABLE IF NOT EXISTS reports (
          id UUID PRIMARY KEY,
          scan_id UUID NOT NULL,
          type VARCHAR(50) NOT NULL,
          format VARCHAR(10) NOT NULL,
          template VARCHAR(100) NOT NULL,
          sections JSONB NOT NULL,
          generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          download_url TEXT NOT NULL,
          expires_at TIMESTAMP NOT NULL,
          size BIGINT NOT NULL,
          report_data JSONB NOT NULL, /* New column to store report content */
          FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
      `;
    }
  }

  async executeQuery(sql: string, params: any[] = []): Promise<any> {
    if (this.dbType === 'sqlite') {
      return this.executeSQLiteQuery(sql, params);
    } else {
      return this.executePostgreSQLQuery(sql, params);
    }
  }

  private async executeSQLiteQuery(sql: string, params: any[] = []): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.sqliteDb) {
        reject(new Error('SQLite database not initialized'));
        return;
      }

      if (sql.trim().toLowerCase().startsWith('select')) {
        this.sqliteDb.all(sql, params, (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      } else {
        this.sqliteDb.run(sql, params, function(err) {
          if (err) reject(err);
          else resolve({ lastID: this.lastID, changes: this.changes });
        });
      }
    });
  }

  private async executePostgreSQLQuery(sql: string, params: any[] = []): Promise<any> {
    if (!this.pgClient) {
      throw new Error('PostgreSQL client not initialized');
    }

    const result = await this.pgClient.query(sql, params);
    return result.rows;
  }

  // User operations
  async createUser(user: Omit<User, 'createdAt' | 'updatedAt'>): Promise<User> {
    const sql = `
      INSERT INTO users (id, email, password_hash, role)
      VALUES (?, ?, ?, ?)
    `;
    
    await this.executeQuery(sql, [user.id, user.email, user.passwordHash, user.role]);
    
    return {
      ...user,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const sql = 'SELECT * FROM users WHERE email = ?';
    const rows = await this.executeQuery(sql, [email]);
    
    if (rows.length === 0) return null;
    
    const row = rows[0];
    return {
      id: row.id,
      email: row.email,
      passwordHash: row.password_hash,
      role: row.role,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
      lastLoginAt: row.last_login_at ? new Date(row.last_login_at) : undefined,
    };
  }

  async updateUserLastLogin(userId: string): Promise<void> {
    const sql = 'UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?';
    await this.executeQuery(sql, [userId]);
  }

  // Scan operations
  async createScan(scan: Omit<Scan, 'createdAt' | 'updatedAt'>): Promise<Scan> {
    const sql = `
      INSERT INTO scans (id, user_id, target_config, scan_config, status, progress, current_step, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    await this.executeQuery(sql, [
      scan.id,
      scan.userId,
      JSON.stringify(scan.target),
      JSON.stringify(scan.configuration),
      scan.status,
      scan.progress,
      scan.currentStep,
      JSON.stringify(scan.metadata),
    ]);
    
    return {
      ...scan,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  async updateScan(scanId: string, updates: Partial<Scan>): Promise<void> {
    const setClause = [];
    const params = [];

    if (updates.status) {
      setClause.push('status = ?');
      params.push(updates.status);
    }
    if (updates.progress !== undefined) {
      setClause.push('progress = ?');
      params.push(updates.progress);
    }
    if (updates.currentStep) {
      setClause.push('current_step = ?');
      params.push(updates.currentStep);
    }
    if (updates.summary) {
      setClause.push('summary = ?');
      params.push(JSON.stringify(updates.summary));
    }

    setClause.push('updated_at = CURRENT_TIMESTAMP');
    params.push(scanId);

    const sql = `UPDATE scans SET ${setClause.join(', ')} WHERE id = ?`;
    await this.executeQuery(sql, params);
  }

  async getScan(scanId: string): Promise<Scan | null> {
    const sql = 'SELECT * FROM scans WHERE id = ?';
    const rows = await this.executeQuery(sql, [scanId]);
    
    if (rows.length === 0) return null;
    
    const row = rows[0];
    return {
      id: row.id,
      userId: row.user_id,
      target: JSON.parse(row.target_config),
      configuration: JSON.parse(row.scan_config),
      status: row.status,
      progress: row.progress,
      currentStep: row.current_step,
      summary: row.summary ? JSON.parse(row.summary) : undefined,
      vulnerabilities: [], // Will be loaded separately
      metadata: JSON.parse(row.metadata),
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  }

  async getUserScans(userId: string, limit: number = 50): Promise<Scan[]> {
    const sql = 'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?';
    const rows = await this.executeQuery(sql, [userId, limit]);
    
    return rows.map((row: any) => ({
      id: row.id,
      userId: row.user_id,
      target: JSON.parse(row.target_config),
      configuration: JSON.parse(row.scan_config),
      status: row.status,
      progress: row.progress,
      currentStep: row.current_step,
      summary: row.summary ? JSON.parse(row.summary) : undefined,
      vulnerabilities: [],
      metadata: JSON.parse(row.metadata),
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    }));
  }

  // Vulnerability operations
  async createVulnerability(vulnerability: Vulnerability): Promise<void> {
    const sql = `
      INSERT INTO vulnerabilities (
        id, scan_id, type, severity, endpoint, method, parameter, payload,
        description, impact, confidence, cwe, cvss, evidence, ai_analysis, remediation
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    await this.executeQuery(sql, [
      vulnerability.id,
      vulnerability.scanId,
      vulnerability.type,
      vulnerability.severity,
      vulnerability.endpoint,
      vulnerability.method,
      vulnerability.parameter,
      vulnerability.payload,
      vulnerability.description,
      vulnerability.impact,
      vulnerability.confidence,
      vulnerability.cwe,
      vulnerability.cvss,
      JSON.stringify(vulnerability.evidence),
      vulnerability.aiAnalysis ? JSON.stringify(vulnerability.aiAnalysis) : null,
      JSON.stringify(vulnerability.remediation),
    ]);
  }

  async getScanVulnerabilities(scanId: string): Promise<Vulnerability[]> {
    const sql = 'SELECT * FROM vulnerabilities WHERE scan_id = ?';
    const rows = await this.executeQuery(sql, [scanId]);
    
    return rows.map((row: any) => ({
      id: row.id,
      scanId: row.scan_id,
      type: row.type,
      severity: row.severity,
      endpoint: row.endpoint,
      method: row.method,
      parameter: row.parameter,
      payload: row.payload,
      description: row.description,
      impact: row.impact,
      confidence: row.confidence,
      cwe: row.cwe,
      cvss: row.cvss,
      evidence: JSON.parse(row.evidence),
      aiAnalysis: row.ai_analysis ? JSON.parse(row.ai_analysis) : undefined,
      remediation: JSON.parse(row.remediation),
      discoveredAt: new Date(row.discovered_at),
    }));
  }

  async saveReport(report: Report, reportData: string): Promise<void> {
    const sql = this.dbType === 'sqlite' ? 
      `INSERT INTO reports (id, scan_id, type, format, template, sections, generated_at, download_url, expires_at, size, report_data)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)` :
      `INSERT INTO reports (id, scan_id, type, format, template, sections, generated_at, download_url, expires_at, size, report_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`;
    const params = [
      report.id,
      report.scanId,
      report.type,
      report.format,
      report.template,
      this.dbType === 'sqlite' ? JSON.stringify(report.sections) : report.sections,
      report.generatedAt.toISOString(),
      report.downloadUrl,
      report.expiresAt.toISOString(),
      report.size,
      reportData,
    ];
    await this.executeQuery(sql, params);
  }

  async getReport(reportId: string): Promise<{ data: string; format: string } | null> {
    const sql = this.dbType === 'sqlite' ? 
      `SELECT report_data, format, expires_at FROM reports WHERE id = ?` :
      `SELECT report_data, format, expires_at FROM reports WHERE id = $1`;
    const params = [reportId];
    const row = await this.executeQuery(sql, params);
    
    if (!row || row.length === 0) return null;

    const report = row[0];
    const expiresAt = new Date(report.expires_at);

    if (expiresAt < new Date()) {
      // Report expired, delete it (optional, but good for cleanup)
      await this.deleteReport(reportId);
      return null;
    }

    return { data: report.report_data, format: report.format };
  }

  async deleteReport(reportId: string): Promise<void> {
    const sql = this.dbType === 'sqlite' ? 
      `DELETE FROM reports WHERE id = ?` :
      `DELETE FROM reports WHERE id = $1`;
    const params = [reportId];
    await this.executeQuery(sql, params);
  }

  async getReportsByScanId(scanId: string): Promise<Report[]> {
    const sql = this.dbType === 'sqlite' ?
      `SELECT id, scan_id, type, format, template, sections, generated_at, download_url, expires_at, size
       FROM reports WHERE scan_id = ?` :
      `SELECT id, scan_id, type, format, template, sections, generated_at, download_url, expires_at, size
       FROM reports WHERE scan_id = $1`;
    const params = [scanId];
    const rows = await this.executeQuery(sql, params);

    return rows.map((row: any) => ({
      id: row.id,
      scanId: row.scan_id,
      type: row.type,
      format: row.format,
      template: row.template,
      sections: this.dbType === 'sqlite' ? JSON.parse(row.sections) : row.sections,
      generatedAt: new Date(row.generated_at),
      downloadUrl: row.download_url,
      expiresAt: new Date(row.expires_at),
      size: row.size,
    }));
  }

  async close(): Promise<void> {
    if (this.sqliteDb) {
      return new Promise((resolve, reject) => {
        this.sqliteDb!.close((err) => {
          if (err) reject(err);
          else {
            logger.info('SQLite database connection closed');
            resolve();
          }
        });
      });
    }
    
    if (this.pgClient) {
      await this.pgClient.end();
      logger.info('PostgreSQL database connection closed');
    }
  }
}

export const database = new Database(); 