/**
 * GhostPrompt JS/TS SDK
 * Drop-in replacement for OpenAI SDK with built-in prompt firewalling.
 */

export class GhostPrompt {
  constructor(config = {}) {
    this.apiKey = config.apiKey || process.env.GHOSTPROMPT_API_KEY;
    this.baseURL = config.baseURL || 'https://api.ghostprompt.com/v1';
    this.sensitivity = config.sensitivity || 'BALANCED';
    this.provider = config.provider || 'openai'; // default provider
    
    // Mimic OpenAI SDK structure
    this.chat = {
      completions: {
        create: async (params) => {
          return this._createCompletion(params);
        }
      }
    };
  }

  async _createCompletion(params) {
    const { model, messages, stream, sessionId, ...rest } = params;
    
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
      'X-GhostPrompt-Sensitivity': this.sensitivity,
      'X-GhostPrompt-Provider': this.provider
    };

    if (sessionId) {
      headers['X-GhostPrompt-Session-Id'] = sessionId;
    }

    const payload = {
      model,
      messages,
      stream,
      ...rest
    };

    try {
      const response = await fetch(`${this.baseURL}/chat/completions`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorText = await response.text();
        let errorObj;
        try {
          errorObj = JSON.parse(errorText);
        } catch(e) {
          errorObj = { message: errorText };
        }
        throw new Error(`GhostPrompt API Error: ${response.status} - ${errorObj.error?.message || errorObj.message || 'Unknown error'}`);
      }

      if (stream) {
        // Implement SSE streaming
        return this._handleStream(response);
      }

      return await response.json();
    } catch (error) {
      throw error;
    }
  }

  async *_handleStream(response) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      
      const chunk = decoder.decode(value, { stream: true });
      const lines = chunk.split('\n').filter(line => line.trim() !== '');
      
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6);
          if (data === '[DONE]') return;
          
          try {
            yield JSON.parse(data);
          } catch (e) {
            console.error('Failed to parse stream data:', e);
          }
        }
      }
    }
  }
}
