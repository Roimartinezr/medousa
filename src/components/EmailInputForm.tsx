import { useState } from 'react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { validateEmail } from '@/utils/validation';
import { Search, Loader2 } from 'lucide-react';

interface EmailInputFormProps {
  onSubmit: (email: string) => void;
  isLoading: boolean;
}

export const EmailInputForm = ({ onSubmit, isLoading }: EmailInputFormProps) => {
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [touched, setTouched] = useState(false);

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setEmail(value);
    
    if (touched && value) {
      if (!validateEmail(value)) {
        setError('Formato de email inválido');
      } else {
        setError('');
      }
    }
  };

  const handleBlur = () => {
    setTouched(true);
    if (email && !validateEmail(email)) {
      setError('Formato de email inválido');
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateEmail(email)) {
      setError('Por favor, introduce un email válido');
      setTouched(true);
      return;
    }

    onSubmit(email);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      setEmail('');
      setError('');
      setTouched(false);
    }
  };

  const isValid = email && validateEmail(email);

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="email" className="text-sm font-medium">
          Dirección de correo electrónico
        </Label>
        <div className="flex gap-2">
          <div className="flex-1">
            <Input
              id="email"
              type="email"
              placeholder="usuario@ejemplo.com"
              value={email}
              onChange={handleEmailChange}
              onBlur={handleBlur}
              onKeyDown={handleKeyDown}
              disabled={isLoading}
              className={error && touched ? 'border-destructive focus-visible:ring-destructive' : ''}
              aria-invalid={error && touched ? 'true' : 'false'}
              aria-describedby={error && touched ? 'email-error' : undefined}
            />
            {error && touched && (
              <p id="email-error" className="text-sm text-destructive mt-1" role="alert">
                {error}
              </p>
            )}
          </div>
          <Button 
            type="submit" 
            disabled={!isValid || isLoading}
            className="min-w-[120px]"
          >
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Analizando
              </>
            ) : (
              <>
                <Search className="mr-2 h-4 w-4" />
                Analizar
              </>
            )}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          Presiona Enter para analizar o Esc para limpiar
        </p>
      </div>
    </form>
  );
};
