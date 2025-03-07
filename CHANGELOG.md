# expo-rsa-generator

## 1.0.5

### Patch Changes

- fdb4c48: fix kotlin path for native module in android

## 1.0.4

### Patch Changes

- 1cec9c7: updated package.json

## 1.0.3

### Patch Changes

- dc824c7: updated module name in expo-config

## 1.0.2

### Patch Changes

- 94294e3: fix gradle

## 1.0.1

### Patch Changes

- 5433cc6: Fixed Autolink in android and ios

## 1.0.0

### Major Changes

- 35d6b3d: # expo-rsa-generator Release Summary

  This release introduces improvements and fixes to the `expo-rsa-generator` package, enhancing its reliability and usability for Expo developers.

  ## Key Changes:

  - **Native Code Enhancements:**
    - Improved error handling in both iOS and Android native code for more robust key generation, encryption, and decryption processes.
    - Ensured consistent key storage and retrieval using platform-specific secure storage mechanisms.
    - Added key alias as a parameter to the key generation function, providing more flexibility for key management.
  - **TypeScript Definitions:**
    - Refined TypeScript definitions to accurately reflect the native module's API, improving developer experience and type safety.
  - **Example App Improvements:**
    - Enhanced the example app with clearer UI elements and improved error handling using alerts, making it easier to test and understand the module's functionality.
    - Added better UI display of the public key, encrypted text, and decrypted text.
  - **Build and Release Process:**
    - Improved the GitHub Actions workflow to include `npx expo prebuild --clean` and `npx pod-install` steps, ensuring consistent builds and releases.
    - Added Plugin folder dependency installation.
    - Updated the package.json pub command to use pnpm.
  - **Dependency Updates:**
    - Updated development dependencies, including `@changesets/cli`.

  ## Notable Fixes:

  - Addressed potential issues with key retrieval on iOS and Android.
  - Resolved compilation errors in the Android native module.
  - Fixed errors relating to the companion object in the android native module.

  ## Impact:

  These changes contribute to a more stable and user-friendly `expo-rsa-generator` package, empowering developers to easily implement RSA cryptography in their Expo applications.
