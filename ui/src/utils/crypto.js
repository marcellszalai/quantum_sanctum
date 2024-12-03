// src/utils/crypto.js

// Function to encrypt data using AES-GCM
export const encryptData = async (aesKey, plaintext) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce
  
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      aesKey,
      data
    );
  
    const ciphertext = btoa(String.fromCharCode(...new Uint8Array(ciphertextBuffer)));
    const ivHex = Array.from(iv)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  
    return { ciphertext, iv: ivHex };
  };
  
  // Function to decrypt data using AES-GCM
  export const decryptData = async (aesKey, ciphertextB64, ivHex) => {
    const ciphertext = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0)).buffer;
    const iv = Uint8Array.from(hexToUint8Array(ivHex));
  
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      aesKey,
      ciphertext
    );
  
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  };
  
  // Function to generate a random salt (for demonstration purposes)
  export const generateRandomSalt = () => {
    return Math.random().toString(36).substring(2, 15);
  };
  
  // Utility function to convert hex to Uint8Array
  const hexToUint8Array = (hex) => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  };  