/**
 * GhostPrompt JavaScript/TypeScript SDK
 *
 * Official client for the GhostPrompt AI Runtime Security Platform.
 * Works in Node.js, Deno, and modern browsers.
 *
 * Usage:
 *   import { GhostPrompt } from '@ghostprompt/sdk';
 *   const gp = new GhostPrompt({ apiKey: 'gp_live_...' });
 *   const result = await gp.scan('Hello world');
 */

export interface GhostPromptConfig {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
  autoBlock?: boolean;
}

export interface Detection {
  detector: string;
  confidence: number;
  category: string;
  description: string;
  matched_content?: string;
  severity: string;
}

export interface ScanResult {
  request_id: string;
  threat_level: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  threat_score: number;
  action: 'allowed' | 'blocked' | 'flagged';
  detections: Detection[];
  scan_duration_ms: number;
}

export interface ScanOptions {
  scanType?: 'prompt' | 'output' | 'rag' | 'agent';
  model?: string;
  provider?: string;
  metadata?: Record<string, unknown>;
}

export class ScanBlockedError extends Error {
  result: ScanResult;

  constructor(result: ScanResult) {
    super(
      `Request blocked by GhostPrompt: threat_level=${result.threat_level}, ` +
      `score=${result.threat_score.toFixed(2)}, ` +
      `detections=${result.detections.length}`
    );
    this.name = 'ScanBlockedError';
    this.result = result;
  }
}

export class GhostPrompt {
  private apiKey: string;
  private baseUrl: string;
  private timeout: number;
  private autoBlock: boolean;

  constructor(config: GhostPromptConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl || 'https://api.ghostprompt.ai').replace(/\/$/, '');
    this.timeout = config.timeout || 30000;
    this.autoBlock = config.autoBlock ?? true;
  }

  async scan(prompt: string, options: ScanOptions = {}): Promise<ScanResult> {
    const response = await fetch(`${this.baseUrl}/api/v1/scan`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'ghostprompt-js/1.0.0',
      },
      body: JSON.stringify({
        prompt,
        scan_type: options.scanType || 'prompt',
        model: options.model,
        provider: options.provider,
        metadata: options.metadata,
      }),
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!response.ok) {
      throw new Error(`GhostPrompt API error: ${response.status} ${response.statusText}`);
    }

    const result: ScanResult = await response.json();

    if (this.autoBlock && result.action === 'blocked') {
      throw new ScanBlockedError(result);
    }

    return result;
  }

  async scanOutput(output: string, model?: string): Promise<ScanResult> {
    return this.scan(output, { scanType: 'output', model });
  }

  async scanRagContext(documents: string[], model?: string): Promise<ScanResult[]> {
    return Promise.all(
      documents.map(doc => this.scan(doc, { scanType: 'rag', model }))
    );
  }

  protect(model?: string) {
    const self = this;
    return function <T extends (...args: any[]) => Promise<string>>(
      target: T
    ): T {
      return (async function (...args: any[]) {
        const prompt = String(args[0]);
        await self.scan(prompt, { model });
        const result = await target(...args);
        return result;
      }) as unknown as T;
    };
  }

  async health(): Promise<Record<string, unknown>> {
    const response = await fetch(`${this.baseUrl}/health`);
    return response.json();
  }
}

export default GhostPrompt;
