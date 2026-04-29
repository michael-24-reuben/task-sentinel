export interface HashProvider {
  sha256(filePath: string): Promise<string | undefined>;
}