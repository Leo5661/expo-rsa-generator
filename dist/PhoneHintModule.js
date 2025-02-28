"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const react_native_1 = require("react-native");
const { PhoneHintModule } = react_native_1.NativeModules;
const PhoneHint = {
    getPhoneHint: async () => {
        if (react_native_1.Platform.OS === 'android') {
            try {
                return await PhoneHintModule.getPhoneHint();
            }
            catch (error) {
                throw new Error(error.message);
            }
        }
        else {
            throw new Error('Phone Hint API is only available on Android');
        }
    },
};
exports.default = PhoneHint;
