import { requireNativeModule } from 'expo';
import { NativeModule } from 'react-native';

interface ExpoRsaGeneratorModule extends NativeModule {
  generateRSAKeyPair(keyAlias: string): Promise<string>;
  encryptRSA(keyAlias: string, data: string): Promise<string>;
  decryptRSA(keyAlias: string, encryptedBase64: string): Promise<string>;
}

interface ExpoEccGeneratorModule extends NativeModule {
  generateECCKeyPair(keyAlias: string): Promise<string>;
  encryptECC(keyAlias: string, data: string): Promise<string>;
  decryptECC(keyAlias: string, encryptedBase64: string): Promise<string>;
}

export const ExpoRsaGenerator = requireNativeModule<ExpoRsaGeneratorModule>('ExpoRsaGenerator');
export const ExpoEccGenerator = requireNativeModule<ExpoEccGeneratorModule>('ExpoEccGenerator');
