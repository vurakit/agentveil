/**
 * Agent Veil SDK for Node.js / TypeScript
 *
 * Usage:
 *   import { AgentVeilClient } from '@agentveil/sdk';
 *
 *   const veil = new AgentVeilClient({
 *     proxyUrl: 'http://localhost:8080',
 *     apiKey: 'veil_sk_...',
 *   });
 *
 *   // Use as drop-in replacement for OpenAI
 *   const response = await veil.chat({
 *     model: 'gpt-4',
 *     messages: [{ role: 'user', content: 'Hello' }],
 *   });
 */

export interface AgentVeilConfig {
  /** Agent Veil proxy URL (default: http://localhost:8080) */
  proxyUrl?: string;
  /** Agent Veil API key */
  apiKey?: string;
  /** Provider API key (OpenAI, Anthropic, etc.) */
  providerApiKey?: string;
  /** Default provider to route to */
  provider?: string;
  /** Session ID for PII token continuity */
  sessionId?: string;
  /** User role for data masking */
  role?: 'admin' | 'viewer' | 'operator';
  /** Request timeout in ms (default: 30000) */
  timeout?: number;
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface ChatRequest {
  model: string;
  messages: ChatMessage[];
  max_tokens?: number;
  temperature?: number;
  stream?: boolean;
}

export interface ChatChoice {
  index: number;
  message: ChatMessage;
  finish_reason: string;
}

export interface ChatUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatResponse {
  id: string;
  model: string;
  choices: ChatChoice[];
  usage: ChatUsage;
}

export interface ScanResult {
  found: boolean;
  entities: PIIEntity[];
}

export interface PIIEntity {
  type: string;
  value: string;
  start: number;
  end: number;
  confidence: number;
}

export interface AuditReport {
  findings: AuditFinding[];
  risk_level: number;
  risk_level_label: string;
  compliance_score: number;
  summary: string;
}

export interface AuditFinding {
  line: number;
  severity: string;
  category: string;
  description: string;
  snippet: string;
}

export class AgentVeilClient {
  private config: Required<
    Pick<AgentVeilConfig, 'proxyUrl' | 'timeout'>
  > & AgentVeilConfig;

  constructor(config: AgentVeilConfig = {}) {
    this.config = {
      proxyUrl: config.proxyUrl || process.env.VEIL_PROXY_URL || 'http://localhost:8080',
      timeout: config.timeout || 30000,
      ...config,
    };
  }

  /**
   * Send a chat completion request through Agent Veil proxy.
   * PII is automatically anonymized before reaching the LLM.
   */
  async chat(request: ChatRequest): Promise<ChatResponse> {
    const headers = this.buildHeaders();
    const url = `${this.config.proxyUrl}/v1/chat/completions`;

    const response = await this.fetch(url, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new AgentVeilError(`Chat request failed: ${response.status}`, response.status, error);
    }

    return response.json() as Promise<ChatResponse>;
  }

  /**
   * Stream a chat completion response.
   * Returns an async iterator of SSE events.
   */
  async *chatStream(request: ChatRequest): AsyncGenerator<string> {
    const headers = this.buildHeaders();
    headers['Accept'] = 'text/event-stream';
    const url = `${this.config.proxyUrl}/v1/chat/completions`;

    const response = await this.fetch(url, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...request, stream: true }),
    });

    if (!response.ok) {
      throw new AgentVeilError(`Stream request failed: ${response.status}`, response.status);
    }

    const reader = response.body?.getReader();
    if (!reader) throw new AgentVeilError('No response body', 0);

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6).trim();
          if (data === '[DONE]') return;
          yield data;
        }
      }
    }
  }

  /**
   * Scan text for PII entities without sending to LLM.
   */
  async scan(text: string): Promise<ScanResult> {
    const headers = this.buildHeaders();
    const url = `${this.config.proxyUrl}/scan`;

    const response = await this.fetch(url, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });

    if (!response.ok) {
      throw new AgentVeilError(`Scan failed: ${response.status}`, response.status);
    }

    return response.json() as Promise<ScanResult>;
  }

  /**
   * Audit a skill.md file for security compliance.
   */
  async audit(content: string): Promise<AuditReport> {
    const headers = this.buildHeaders();
    const url = `${this.config.proxyUrl}/audit`;

    const response = await this.fetch(url, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });

    if (!response.ok) {
      throw new AgentVeilError(`Audit failed: ${response.status}`, response.status);
    }

    return response.json() as Promise<AuditReport>;
  }

  /**
   * Health check the Agent Veil proxy.
   */
  async health(): Promise<{ status: string }> {
    const response = await this.fetch(`${this.config.proxyUrl}/health`);
    return response.json() as Promise<{ status: string }>;
  }

  /**
   * Get the proxy URL for use as OPENAI_BASE_URL / ANTHROPIC_BASE_URL.
   */
  getBaseURL(): string {
    return `${this.config.proxyUrl}/v1`;
  }

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {};

    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    } else if (this.config.providerApiKey) {
      headers['Authorization'] = `Bearer ${this.config.providerApiKey}`;
    }

    if (this.config.sessionId) {
      headers['X-Session-ID'] = this.config.sessionId;
    }
    if (this.config.role) {
      headers['X-User-Role'] = this.config.role;
    }
    if (this.config.provider) {
      headers['X-Veil-Provider'] = this.config.provider;
    }

    return headers;
  }

  private async fetch(url: string, init?: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      return await globalThis.fetch(url, {
        ...init,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

export class AgentVeilError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public body?: string,
  ) {
    super(message);
    this.name = 'AgentVeilError';
  }
}

/**
 * Helper: Get environment-configured Agent Veil client.
 * Reads VEIL_PROXY_URL, VEIL_API_KEY, VEIL_SESSION_ID from env.
 */
export function createClient(overrides?: AgentVeilConfig): AgentVeilClient {
  return new AgentVeilClient({
    proxyUrl: process.env.VEIL_PROXY_URL,
    apiKey: process.env.VEIL_API_KEY,
    sessionId: process.env.VEIL_SESSION_ID,
    ...overrides,
  });
}
