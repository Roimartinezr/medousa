import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';

export const LoadingSkeleton = () => {
  return (
    <div className="space-y-6">
      <Card className="shadow-card">
        <CardHeader>
          <Skeleton className="h-6 w-32" />
          <Skeleton className="h-4 w-48 mt-2" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-8 w-24" />
        </CardContent>
      </Card>

      <Card className="shadow-card">
        <CardHeader>
          <Skeleton className="h-6 w-48" />
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
          </div>
        </CardContent>
      </Card>

      <Card className="shadow-card">
        <CardHeader>
          <Skeleton className="h-6 w-40" />
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between">
            <Skeleton className="h-8 w-16" />
            <Skeleton className="h-6 w-20" />
          </div>
          <Skeleton className="h-2 w-full" />
        </CardContent>
      </Card>
    </div>
  );
};
