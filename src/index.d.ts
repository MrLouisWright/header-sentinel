export type Severity = 'error' | 'warn';
export interface Finding { id: string; severity: Severity; title: string; message: string; fix?: string; }
export interface Result { url: string; requestedUrl?: string; status?: number; error?: string; findings: Finding[]; score: number; grade: string; }
export interface Config {
  urls?: string[];
  ignore?: string[];
  severity?: Record<string, Severity | 'off'>;
  failOn?: 'error' | 'warn' | 'none';
  timeout?: number;
  headers?: Record<string, string>;
}
export interface ScanOptions { timeout?: number; headers?: Record<string, string>; followRedirects?: boolean; config?: Config; }
export interface CheckContext { url: string; headers: Headers; setCookies: string[]; isHttps: boolean; }
export const CHECKS: Record<string, (ctx: CheckContext) => Finding[]>;
export function analyze(input: { url: string; headers: Headers | Record<string, string>; setCookies?: string[] }, config?: Config): Result;
export function scan(url: string, opts?: ScanOptions): Promise<Result>;
export function scanAll(urls: string[], opts?: ScanOptions): Promise<Result[]>;
export function shouldFail(results: Result[], failOn?: 'error' | 'warn' | 'none'): boolean;
export function applyConfig(findings: Finding[], config?: Config): Finding[];
export function grade(score: number): string;
export function toSarif(results: Result[], version?: string): object;
