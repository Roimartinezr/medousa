import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { AnalyzeEmailResponse } from '@/services/apiClient';
import { Copy, Check, Code2 } from 'lucide-react';
import { toast } from '@/hooks/use-toast';

interface JsonViewerProps {
  data: AnalyzeEmailResponse;
}

export const JsonViewer = ({ data }: JsonViewerProps) => {
  const [copied, setCopied] = useState(false);
  const jsonString = JSON.stringify(data, null, 2);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(jsonString);
      setCopied(true);
      toast({
        title: 'Copiado',
        description: 'JSON copiado al portapapeles',
      });
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'No se pudo copiar al portapapeles',
        variant: 'destructive',
      });
    }
  };

  return (
    <Card className="shadow-card">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-xl">
              <Code2 className="h-5 w-5" />
              Respuesta JSON
            </CardTitle>
            <CardDescription>Datos completos de la API</CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopy}
            className="gap-2"
          >
            {copied ? (
              <>
                <Check className="h-4 w-4" />
                Copiado
              </>
            ) : (
              <>
                <Copy className="h-4 w-4" />
                Copiar
              </>
            )}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <pre className="rounded-lg bg-muted p-4 overflow-x-auto">
          <code className="text-sm font-mono">{jsonString}</code>
        </pre>
      </CardContent>
    </Card>
  );
};
