import React, { useState } from 'react';
import { StyleSheet, Text, View, Button, TextInput, ScrollView, Alert } from 'react-native';
import ExpoRsaGenerator from 'expo-rsa-generator';

export default function App() {
  const [keyAlias, setKeyAlias] = useState('MyCustomKeyAlias');
  const [inputText, setInputText] = useState('');
  const [encryptedText, setEncryptedText] = useState('');
  const [decryptedText, setDecryptedText] = useState('');
  const [publicKey, setPublicKey] = useState('');

  const generateKeyPair = async () => {
    try {
      const publicKeyBase64 = await ExpoRsaGenerator.generateRSAKeyPair(keyAlias);
      setPublicKey(publicKeyBase64);
      Alert.alert('Success', 'Key pair generated successfully.');
    } catch (error: any) {
      console.error('Error generating key pair:', error);
      Alert.alert('Error', `Key pair generation failed: ${error.message}`);
    }
  };

  const encryptData = async () => {
    try {
      const encryptedBase64 = await ExpoRsaGenerator.encryptRSA(keyAlias, inputText);
      setEncryptedText(encryptedBase64);
      Alert.alert('Success', 'Encryption successful.');
    } catch (error: any) {
      console.error('Error encrypting data:', error);
      Alert.alert('Error', `Encryption failed: ${error.message}`);
    }
  };

  const decryptData = async () => {
    try {
      const decryptedString = await ExpoRsaGenerator.decryptRSA(keyAlias, encryptedText);
      setDecryptedText(decryptedString);
      Alert.alert('Success', 'Decryption successful.');
    } catch (error: any) {
      console.error('Error decrypting data:', error);
      Alert.alert('Error', `Decryption failed: ${error.message}`);
    }
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <TextInput
        style={styles.input}
        placeholder="Key Alias"
        value={keyAlias}
        onChangeText={setKeyAlias}
      />
      <Button title="Generate Key Pair" onPress={generateKeyPair} />
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
});