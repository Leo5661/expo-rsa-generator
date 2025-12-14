import React, { useState } from 'react';
import { StyleSheet, Text, View, Button, TextInput, ScrollView, Alert } from 'react-native';
import { ExpoRsaGenerator, ExpoEccGenerator } from 'expo-rsa-generator';

export default function App() {
  const [keyAlias, setKeyAlias] = useState('MyCustomKeyAlias');
  const [inputText, setInputText] = useState('');
  const [encryptedText, setEncryptedText] = useState('');
  const [decryptedText, setDecryptedText] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [mode, setMode] = useState<'RSA' | 'ECC'>('RSA');

  const generateKeyPair = async () => {
    try {
      let publicKeyBase64;
      if (mode === 'RSA') {
        publicKeyBase64 = await ExpoRsaGenerator.generateRSAKeyPair(keyAlias);
      } else {
        publicKeyBase64 = await ExpoEccGenerator.generateECCKeyPair(keyAlias);
      }
      setPublicKey(publicKeyBase64);
      Alert.alert('Success', `${mode} Key pair generated successfully.`);
    } catch (error: any) {
      console.error(`Error generating ${mode} key pair:`, error);
      Alert.alert('Error', `${mode} Key pair generation failed: ${error.message}`);
    }
  };

  const encryptData = async () => {
    try {
      let encryptedBase64;
      if (mode === 'RSA') {
        encryptedBase64 = await ExpoRsaGenerator.encryptRSA(keyAlias, inputText);
      } else {
        encryptedBase64 = await ExpoEccGenerator.encryptECC(keyAlias, inputText);
      }
      console.log('encryptedBase64', encryptedBase64);
      setEncryptedText(encryptedBase64);
      Alert.alert('Success', 'Encryption successful.');
    } catch (error: any) {
      console.error('Error encrypting data:', error);
      Alert.alert('Error', `Encryption failed: ${error.message}`);
    }
  };

  const decryptData = async () => {
    try {
      console.log('encryptedText', encryptedText);
      let decryptedString;
      if (mode === 'RSA') {
        decryptedString = await ExpoRsaGenerator.decryptRSA(keyAlias, encryptedText);
      } else {
        decryptedString = await ExpoEccGenerator.decryptECC(keyAlias, encryptedText);
      }
      setDecryptedText(decryptedString);
      Alert.alert('Success', 'Decryption successful.');
    } catch (error: any) {
      console.error('Error decrypting data:', error);
      Alert.alert('Error', `Decryption failed: ${error.message}`);
    }
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.header}>{mode} Mode</Text>
      <View style={styles.buttonContainer}>
        <Button title="Switch to RSA" onPress={() => setMode('RSA')} disabled={mode === 'RSA'} />
        <Button title="Switch to ECC" onPress={() => setMode('ECC')} disabled={mode === 'ECC'} />
      </View>

      <TextInput
        style={styles.input}
        placeholder="Key Alias"
        value={keyAlias}
        onChangeText={setKeyAlias}
      />
      <Button title={`Generate ${mode} Key Pair`} onPress={generateKeyPair} />
      {publicKey ? <Text>Public Key: {publicKey.substring(0, 50)}... </Text> : null}

      <TextInput
        style={styles.input}
        placeholder="Enter text to encrypt"
        value={inputText}
        onChangeText={setInputText}
      />
      <Button title="Encrypt" onPress={encryptData} />
      {encryptedText ? <Text>Encrypted: {encryptedText.substring(0, 50)}...</Text> : null}

      <TextInput
        style={styles.input}
        placeholder="Enter text to decrypt"
        value={encryptedText}
        onChangeText={setEncryptedText}
      />
      <Button title="Decrypt" onPress={decryptData} />
      {decryptedText ? <Text>Decrypted: {decryptedText.substring(0, 50)}</Text> : null}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
  },
  input: {
    height: 40,
    borderColor: 'gray',
    borderWidth: 1,
    width: '100%',
    marginBottom: 10,
    paddingHorizontal: 10,
  },
  header: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 20,
  },
  buttonContainer: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    width: '100%',
    marginBottom: 20,
  },
});