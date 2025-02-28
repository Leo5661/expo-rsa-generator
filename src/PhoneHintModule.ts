import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'rn-phone-hint' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go - you need to create a development build';

const PhoneHintModule = NativeModules.PhoneHintModule
  ? NativeModules.PhoneHintModule
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

const PhoneHint = {
  getPhoneHint: async (): Promise<string | null> => {
    try {
      return await PhoneHintModule.getPhoneHint();
    } catch (error: any) {
      throw new Error(error.message);
    }
  },
};

export default PhoneHint;