const API_URL = import.meta.env.VITE_API_URL || '';

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
  const response = await fetch(`http://localhost:8000/validate`, {
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
