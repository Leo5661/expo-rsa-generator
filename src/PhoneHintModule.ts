import { NativeModules, Platform } from 'react-native';

const { PhoneHintModule } = NativeModules;

const PhoneHint = {
    getPhoneHint: async (): Promise<string | null> => {
        if (Platform.OS === 'android') {
            try {
                return await PhoneHintModule.getPhoneHint();
            } catch (error:any) {
                throw new Error(error.message);
            }
        } else {
            throw new Error('Phone Hint API is only available on Android');
        }
    },
};

export default PhoneHint;