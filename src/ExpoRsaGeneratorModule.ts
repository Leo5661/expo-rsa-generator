import { requireNativeModule } from 'expo';
import { NativeModule } from 'react-native';

interface ExpoRsaGeneratorModule extends NativeModule {
  generateRSAKeyPair(keyAlias: string): Promise<string>;
  encryptRSA(keyAlias: string, data: string): Promise<string>;
  decryptRSA(keyAlias: string, encryptedBase64: string): Promise<string>;
}

export default requireNativeModule<ExpoRsaGeneratorModule>('ExpoRsaGenerator');
