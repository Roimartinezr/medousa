import { useState, useMemo } from 'react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { AnalyzeEmailResponse } from '@/services/apiClient';
import { getConfidenceLevel } from '@/utils/validation';
import { History, Search } from 'lucide-react';
import { format } from 'date-fns';
import { es } from 'date-fns/locale';

interface HistoryEntry {
  timestamp: Date;
  result: AnalyzeEmailResponse;
}

interface HistoryTableProps {
  history: HistoryEntry[];
}

export const HistoryTable = ({ history }: HistoryTableProps) => {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredHistory = useMemo(() => {
    if (!searchTerm) return history;
    
    const term = searchTerm.toLowerCase();
    return history.filter(entry => 
      entry.result.email.toLowerCase().includes(term) ||
      entry.result.veredict.toLowerCase().includes(term) ||
      entry.result.labels.some(label => label.toLowerCase().includes(term))
    );
  }, [history, searchTerm]);

  if (history.length === 0) {
    return (
      <Card className="shadow-card">
        <CardContent className="py-8">
          <p className="text-center text-muted-foreground">
            No hay consultas en el historial
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="shadow-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-xl">
          <History className="h-5 w-5" />
          Historial de Consultas
        </CardTitle>
        <CardDescription>
          {history.length} {history.length === 1 ? 'consulta realizada' : 'consultas realizadas'}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Buscar por email, veredicto o etiquetas..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9"
          />
        </div>

        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Fecha</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Veredicto</TableHead>
                <TableHead>Confianza</TableHead>
                <TableHead>Empresa Suplantada</TableHead>
                <TableHead>Empresa Detectada</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredHistory.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">
                    No se encontraron resultados
                  </TableCell>
                </TableRow>
              ) : (
                filteredHistory.map((entry, index) => {
                  const isValid = entry.result.veredict === 'valid';
                  const isPhishing = entry.result.veredict === 'phishing';
                  const confidenceLevel = getConfidenceLevel(entry.result.confidence);
                  
                  return (
                    <TableRow key={index}>
                      <TableCell className="font-medium">
                        {format(entry.timestamp, "dd MMM yyyy HH:mm", { locale: es })}
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {entry.result.email}
                      </TableCell>
                      <TableCell>
                        <Badge variant={isValid ? 'default' : isPhishing ? 'destructive' : 'warning'} className={isValid ? 'bg-success hover:bg-success/90' : ''}>
                          {isValid ? 'Valid' : isPhishing ? 'Phishing' : 'Warning'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">
                            {Math.round(entry.result.confidence * 100)}%
                          </span>
                          <Badge variant="outline" className="text-xs">
                            {confidenceLevel.label}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell>
                        {entry.result.company_impersonated || (
                          <span className="text-muted-foreground text-sm">No determinado</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {entry.result.company_detected || (
                          <span className="text-muted-foreground text-sm">No determinado</span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
};
