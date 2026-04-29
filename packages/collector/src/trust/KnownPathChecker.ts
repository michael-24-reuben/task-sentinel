export interface KnownPathChecker {
  isKnownPath(filePath: string): Promise<boolean>;
}