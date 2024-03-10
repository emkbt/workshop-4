import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};

// Generates a pair of private/public RSA keys
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP", // Algorithm for RSA encryption with OAEP padding
      modulusLength: 2048, // Length of RSA key modulus in bits
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // Public exponent for RSA key generation
      hash: "SHA-256", // Hash algorithm for RSA-OAEP
    },
    true, // Whether the generated key pair should be extractable
    ["encrypt", "decrypt"] // Key usages
  );

  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(exportedKey);
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(key: webcrypto.CryptoKey | null): Promise<string | null> {
  if (key === null) {
    return null;
  }
  
  const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64(exportedKey);
}

// Import a base64 string public key to its native format
export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    "spki", // Format of the key data
    keyBuffer,
    {
      name: "RSA-OAEP", // Algorithm name
      hash: "SHA-256" // Hash algorithm
    },
    true, // Whether the key is extractable
    ["encrypt"] // Key usages
  );
}

// Import a base64 string private key to its native format
export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    "pkcs8", // Format of the key data
    keyBuffer,
    {
      name: "RSA-OAEP", // Algorithm name
      hash: "SHA-256" // Hash algorithm
    },
    true, // Whether the key is extractable
    ["decrypt"] // Key usages
  );
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(b64Data: string, strPublicKey: string): Promise<string> {
  const publicKey = await importPubKey(strPublicKey);
  const data = base64ToArrayBuffer(b64Data);
  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP", // Algorithm name
    },
    publicKey,
    data
  );
  return arrayBufferToBase64(encryptedData);
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(data: string, privateKey: webcrypto.CryptoKey): Promise<string> {
  const dataBuffer = base64ToArrayBuffer(data);
  const decryptedData = await webcrypto.subtle.decrypt(
    { 
      name: "RSA-OAEP", // Algorithm name
    },
    privateKey,
    dataBuffer
  );
  return arrayBufferToBase64(decryptedData);
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  return await webcrypto.subtle.generateKey(
    {
      name: "AES-CBC", // Algorithm name
      length: 256, // Key length in bits
    },
    true, // Whether the generated key should be extractable
    ["encrypt", "decrypt"] // Key usages
  );
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(exportedKey);
}

// Import a base64 string format to its crypto native format
export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    "raw", // Format of the key data
    keyBuffer,
    {
      name: "AES-CBC", // Algorithm name
      length: 256, // Key length in bits
    },
    true, // Whether the key is extractable
    ["encrypt", "decrypt"] // Key usages
  );
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  const dataUint8Array = new TextEncoder().encode(data);
  const iv = crypto.getRandomValues(new Uint8Array(16)); // Initialization Vector
  const encryptedData = await webcrypto.subtle.encrypt(
      {
        name: "AES-CBC", // Algorithm name
        iv: iv, // Initialization Vector
      },
      key,
      dataUint8Array
  );
  const concatenatedData = new Uint8Array([...iv, ...new Uint8Array(encryptedData)]);
  return arrayBufferToBase64(concatenatedData.buffer);
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  const key = await importSymKey(strKey);
  const encryptedDataBuffer = base64ToArrayBuffer(encryptedData);
  const iv = encryptedDataBuffer.slice(0, 16); // Extract Initialization Vector
  const decryptedDataBuffer = await webcrypto.subtle.decrypt(
      {
        name: "AES-CBC", // Algorithm name
        iv: iv, // Initialization Vector
      },
      key,
      encryptedDataBuffer.slice(16) // Exclude IV from the encrypted data
  );
  return new TextDecoder().decode(decryptedDataBuffer);
}