const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

export interface AnalyzeEmailRequest {
  email: string;
}

export interface Evidence {
  type: string;
  value: string;
  score: number;
}

export interface AnalyzeEmailResponse {
  request_id: string;
  email: string;
  veredict: 'valid' | 'phishing';
  veredict_detail?: string;
  company_impersonated: string | null;
  company_detected: string | null;
  confidence: number; // 0.0 - 1.0
  labels: string[];
  evidences?: Evidence[];
}

export interface ApiError {
  error: {
    code: number;
    message: string;
  };
}

export const analyzeEmail = async (email: string): Promise<AnalyzeEmailResponse> => {
  const response = await fetch(`http://localhost:5500/validate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email }),
  });

  if (!response.ok) {
    const errorData: ApiError = await response.json();
    throw new Error(errorData.error.message || 'Error al analizar el email');
  }

  return response.json();
};

// Mock function for development/demo
export const mockAnalyzeEmail = async (email: string): Promise<AnalyzeEmailResponse> => {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 1500));

  // Mock data based on email characteristics
  const isSuspicious = email.includes('admin') || email.includes('support') || email.endsWith('.tk');
  const isCorporate = email.includes('@company.com') || email.includes('@corporation.com');
  
  return {
    request_id: crypto.randomUUID(),
    email,
    veredict: isSuspicious ? 'phishing' : 'valid',
    veredict_detail: isSuspicious 
      ? 'Patrones sospechosos detectados en la dirección'
      : 'La dirección parece legítima',
    company_impersonated: isSuspicious ? 'PayPal' : null,
    company_detected: isCorporate ? 'Tech Corporation' : null,
    confidence: isSuspicious ? 0.25 : 0.85,
    labels: isSuspicious 
      ? ['posible-phishing', 'freemail', 'dominio-sospechoso']
      : isCorporate 
        ? ['dominio-corporativo', 'verificado']
        : ['freemail'],
    evidences: [
      { type: 'Dominio', value: email.split('@')[1], score: isSuspicious ? 0.3 : 0.9 },
      { type: 'Patrones', value: isSuspicious ? 'Sospechosos' : 'Normales', score: isSuspicious ? 0.2 : 0.8 },
      { type: 'Reputación', value: isSuspicious ? 'Baja' : 'Alta', score: isSuspicious ? 0.25 : 0.85 },
    ],
  };
};
