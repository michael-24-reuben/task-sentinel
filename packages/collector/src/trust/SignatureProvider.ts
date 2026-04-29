export interface SignatureProvider {
  readSignature(filePath: string): Promise<{
    publisher?: string;
    isValid?: boolean;
  } | undefined>;
}