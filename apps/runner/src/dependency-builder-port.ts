import { HarnessError } from '@cloud-harness/contracts';

export type DependencyDownloadSpec = {
  id: string;
  imageId: string;
  ecosystem: 'go' | 'pnpm';
  manifests: Record<string, string>;
  stagingDir: string;
  timeoutMs: number;
  maxBytes: number;
  toolMounts: Array<{ source: string; target: string }>;
  binDirs: string[];
  signal?: AbortSignal;
};
export interface DependencyBuilderPort {
  imageId(): Promise<string>;
  download(spec: DependencyDownloadSpec): Promise<{ sizeBytes: number }>;
}

/** Staging must be retained until startup cleanup confirms that no helper can write it. */
export class DependencyCleanupError extends HarnessError {
  constructor() {
    super('UNAVAILABLE', 'dependency download cleanup could not be confirmed', 503, true);
    this.name = 'DependencyCleanupError';
  }
}
