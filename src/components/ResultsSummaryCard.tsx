import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { AnalyzeEmailResponse } from '@/services/apiClient';
import { getConfidenceLevel } from '@/utils/validation';
import { ShieldCheck, ShieldAlert, Building2, Building, TrendingUp } from 'lucide-react';

interface ResultsSummaryCardProps {
  result: AnalyzeEmailResponse;
}

export const ResultsSummaryCard = ({ result }: ResultsSummaryCardProps) => {
  const isPhysical = result.veredict === 'fisico';
  const confidencePercent = Math.round(result.confidence * 100);
  const confidenceLevel = getConfidenceLevel(result.confidence);

  return (
    <div className="space-y-6">
      {/* Veredicto */}
      <Card className="shadow-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            {isPhysical ? (
              <ShieldCheck className="h-5 w-5 text-success" />
            ) : (
              <ShieldAlert className="h-5 w-5 text-destructive" />
            )}
            Veredicto
          </CardTitle>
          <CardDescription>Análisis de la dirección de correo</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-3">
            <Badge 
              variant={isPhysical ? "default" : "destructive"}
              className={isPhysical ? 'bg-success hover:bg-success/90' : ''}
            >
              {isPhysical ? 'Físico' : 'No Físico'}
            </Badge>
            <span className="text-sm text-muted-foreground">
              {result.veredict_detail || 'Sin detalles adicionales'}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Empresas */}
      {(result.company_impersonated || result.company_detected) && (
        <Card className="shadow-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-xl">
              <Building2 className="h-5 w-5" />
              Empresas Relacionadas
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {result.company_impersonated && (
              <div className="flex items-start gap-2">
                <ShieldAlert className="h-4 w-4 text-destructive mt-0.5" />
                <div>
                  <p className="text-sm font-medium">Empresa Suplantada</p>
                  <p className="text-sm text-muted-foreground">{result.company_impersonated}</p>
                </div>
              </div>
            )}
            {result.company_detected && (
              <div className="flex items-start gap-2">
                <Building className="h-4 w-4 text-primary mt-0.5" />
                <div>
                  <p className="text-sm font-medium">Empresa Detectada</p>
                  <p className="text-sm text-muted-foreground">{result.company_detected}</p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Confianza */}
      <Card className="shadow-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            <TrendingUp className="h-5 w-5" />
            Nivel de Confianza
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-2xl font-bold">{confidencePercent}%</span>
            <Badge variant={confidenceLevel.color === 'success' ? 'default' : confidenceLevel.color}>
              {confidenceLevel.label}
            </Badge>
          </div>
          <Progress 
            value={confidencePercent} 
            className="h-2"
          />
        </CardContent>
      </Card>

      {/* Etiquetas */}
      {result.labels.length > 0 && (
        <Card className="shadow-card">
          <CardHeader>
            <CardTitle className="text-xl">Clasificación</CardTitle>
            <CardDescription>Categorías detectadas</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {result.labels.map((label, index) => (
                <Badge key={index} variant="secondary">
                  {label}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
