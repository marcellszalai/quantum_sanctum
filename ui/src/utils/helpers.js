// src/utils/helpers.js

// Example: Function to convert ArrayBuffer to Base64
export const arrayBufferToBase64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach((b) => (binary += String.fromCharCode(b)));
    return window.btoa(binary);
  };
  
  // Example: Function to convert Base64 to ArrayBuffer
  export const base64ToArrayBuffer = (base64) => {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  };  