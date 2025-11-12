import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { EmailInputForm } from '@/components/EmailInputForm';
import { ResultsSummaryCard } from '@/components/ResultsSummaryCard';
import { EvidenceTable } from '@/components/EvidenceTable';
import { JsonViewer } from '@/components/JsonViewer';
import { HistoryTable } from '@/components/HistoryTable';
import { LoadingSkeleton } from '@/components/LoadingSkeleton';
import { analyzeEmail, AnalyzeEmailResponse } from '@/services/apiClient';
import { toast } from '@/hooks/use-toast';
import { AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface HistoryEntry {
  timestamp: Date;
  result: AnalyzeEmailResponse;
}

const STORAGE_KEY = 'email_analysis_history';

const Index = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<AnalyzeEmailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  // Load history from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        // Convert timestamp strings back to Date objects
        const historyWithDates = parsed.map((entry: any) => ({
          ...entry,
          timestamp: new Date(entry.timestamp)
        }));
        setHistory(historyWithDates);
      }
    } catch (error) {
      console.error('Error loading history:', error);
    }
  }, []);

  // Save history to localStorage whenever it changes
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    } catch (error) {
      console.error('Error saving history:', error);
    }
  }, [history]);

  const handleAnalyze = async (email: string) => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      // Using mock API for demo. Replace with: analyzeEmail(email)
      const response = await analyzeEmail(email);
      
      setResult(response);
      
      // Add to history
      const newEntry: HistoryEntry = {
        timestamp: new Date(),
        result: response
      };
      setHistory(prev => [newEntry, ...prev]);

      toast({
        title: 'Análisis completado',
        description: `Email ${email} analizado correctamente`,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al analizar el email';
      setError(errorMessage);
      
      toast({
        title: 'Error en el análisis',
        description: errorMessage,
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleRetry = () => {
    setError(null);
    setResult(null);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/60">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <img
              src="../../public/medousa2.png"
              alt="Khrani icon"
              className="h-20 w-20"
            /> 
            <h1 className="text-2xl font-bold">MEDOUSA</h1>
          </div>
          <p className="text-sm text-muted-foreground hidden md:block">
            Análisis de riesgo de direcciones de correo electrónico
          </p>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        <div className="space-y-8">
          {/* Input Section */}
          <Card className="shadow-card">
            <CardHeader>
              <CardTitle className="text-2xl">Analizar Email</CardTitle>
              <CardDescription>
                Introduce una dirección de correo electrónico para analizar su riesgo y autenticidad
              </CardDescription>
            </CardHeader>
            <CardContent>
              <EmailInputForm onSubmit={handleAnalyze} isLoading={isLoading} />
            </CardContent>
          </Card>

          {/* Error State */}
          {error && (
            <Card className="border-destructive shadow-card">
              <CardContent className="pt-6">
                <div className="flex items-start gap-3">
                  <AlertCircle className="h-5 w-5 text-destructive mt-0.5" />
                  <div className="flex-1">
                    <h3 className="font-semibold text-destructive">Error en el análisis</h3>
                    <p className="text-sm text-muted-foreground mt-1">{error}</p>
                    <Button 
                      onClick={handleRetry} 
                      variant="outline" 
                      size="sm" 
                      className="mt-3"
                    >
                      Reintentar
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Loading State */}
          {isLoading && <LoadingSkeleton />}

          {/* Results */}
          {result && !isLoading && (
            <Tabs defaultValue="summary" className="w-full">
              <TabsList className="grid w-full grid-cols-4">
                <TabsTrigger value="summary">Resumen</TabsTrigger>
                <TabsTrigger value="evidences">Evidencias</TabsTrigger>
                <TabsTrigger value="json">Detalle Crudo</TabsTrigger>
                <TabsTrigger value="history">Historial</TabsTrigger>
              </TabsList>

              <TabsContent value="summary" className="mt-6">
                <ResultsSummaryCard result={result} />
              </TabsContent>

              <TabsContent value="evidences" className="mt-6">
                <EvidenceTable evidences={result.evidences || []} />
              </TabsContent>

              <TabsContent value="json" className="mt-6">
                <JsonViewer data={result} />
              </TabsContent>

              <TabsContent value="history" className="mt-6">
                <HistoryTable history={history} />
              </TabsContent>
            </Tabs>
          )}

          {/* History (when no result) */}
          {!result && !isLoading && history.length > 0 && (
            <div>
              <h2 className="text-xl font-semibold mb-4">Consultas Recientes</h2>
              <HistoryTable history={history} />
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default Index;
