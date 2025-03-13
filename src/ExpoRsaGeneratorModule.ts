import { requireNativeModule } from 'expo';
import { NativeModule } from 'react-native';

interface ExpoRsaGeneratorModule extends NativeModule {
  generateKeyPair(keyAlias: string): Promise<string>;
  encrypt(keyAlias: string, data: string): Promise<string>;
  decrypt(keyAlias: string, encryptedBase64: string): Promise<string>;
}

interface ExpoEccGeneratorModule extends NativeModule {
  generateKeyPair(keyAlias: string): Promise<string>;
  encrypt(keyAlias: string, data: string): Promise<string>;
  decrypt(keyAlias: string, encryptedBase64: string): Promise<string>;
}

export const ExpoRsaGenerator = requireNativeModule<ExpoRsaGeneratorModule>('ExpoRsaGenerator');
export const ExpoEccGenerator = requireNativeModule<ExpoEccGeneratorModule>('ExpoEccGenerator');
