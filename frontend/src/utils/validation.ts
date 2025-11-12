// RFC 5322 simplified email validation
export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

export const getConfidenceLevel = (confidence: number): {
  label: string;
  color: 'destructive' | 'warning' | 'success';
} => {
  if (confidence <= 0.4) {
    return { label: 'Baja', color: 'destructive' };
  } else if (confidence <= 0.7) {
    return { label: 'Media', color: 'warning' };
  } else {
    return { label: 'Alta', color: 'success' };
  }
};
