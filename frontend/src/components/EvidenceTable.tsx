import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Evidence } from '@/services/apiClient';
import { FileText } from 'lucide-react';

interface EvidenceTableProps {
  evidences: Evidence[];
}

export const EvidenceTable = ({ evidences }: EvidenceTableProps) => {
  if (!evidences || evidences.length === 0) {
    return (
      <Card className="shadow-card">
        <CardContent className="py-8">
          <p className="text-center text-muted-foreground">No hay evidencias disponibles</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="shadow-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-xl">
          <FileText className="h-5 w-5" />
          Evidencias Detectadas
        </CardTitle>
        <CardDescription>
          Señales analizadas con su nivel de confianza
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Tipo</TableHead>
              <TableHead>Valor</TableHead>
              <TableHead className="w-[200px]">Puntuación</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {evidences.map((evidence, index) => (
              <TableRow key={index}>
                <TableCell className="font-medium">{evidence.type}</TableCell>
                <TableCell>{evidence.value}</TableCell>
                <TableCell>
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">
                        {Math.round(evidence.score * 100)}%
                      </span>
                    </div>
                    <Progress value={evidence.score * 100} className="h-2" />
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
};
