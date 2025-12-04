import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { FileText } from 'lucide-react';

interface EvidenceTableProps {
  evidences: Evidence[];
}

interface Evidence {
  domain: string;
  owner: string;
  detail: string;
}

export const EvidenceTable = ({ evidences }: EvidenceTableProps) => {
  if (!evidences || evidences.length === 0) {
    return (
      <Card className="shadow-card">
        <CardContent className="py-8">
          <p className="text-center text-muted-foreground">
            No hay evidencias disponibles
          </p>
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
          Dominio y organización asociada con su clasificación
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Dominio</TableHead>
              <TableHead>Organización Registradora</TableHead>
              <TableHead className="w-[200px]">Detalles</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {evidences.map((evidence, index) => (
              <TableRow key={index}>
                <TableCell className="font-medium">{evidence.domain}</TableCell>
                <TableCell>{evidence.owner}</TableCell>
                <TableCell>{evidence.detail}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
};