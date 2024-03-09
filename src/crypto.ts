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
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP", 
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), 
      hash: "SHA-256", 
    },
    true, 
    ["encrypt", "decrypt"] 
  );

  const publicKey = keyPair.publicKey;
  const privateKey = keyPair.privateKey;
  return {publicKey : publicKey, privateKey : privateKey};
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  const exportedKeyBuffer = new Uint8Array(exportedKey);
  return arrayBufferToBase64(exportedKeyBuffer);
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (key === null) {
    return null;
  }
  
  const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);
  const exportedKeyBuffer = new Uint8Array(exportedKey);
  return arrayBufferToBase64(exportedKeyBuffer);
}

// Import a base64 string public key to its native format
export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const publicKey = await webcrypto.subtle.importKey(
    "spki",
    keyBuffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
  return publicKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const privateKey = await webcrypto.subtle.importKey(
    "pkcs8",
    keyBuffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
  return privateKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(b64Data: string, strPublicKey: string): Promise<string> {
  const PublicKey = await importPubKey(strPublicKey)
  const dataencrypt = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    PublicKey,
    base64ToArrayBuffer(b64Data),
  );
  return arrayBufferToBase64(dataencrypt);
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(data: string, privateKey: webcrypto.CryptoKey): Promise<string> {
  const datadecrypt = await webcrypto.subtle.decrypt(
    { 
      name: "RSA-OAEP" 
    },
    privateKey,
    base64ToArrayBuffer(data),
  );
  return arrayBufferToBase64(datadecrypt);
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  let key = await webcrypto.subtle.generateKey(
    {
      name: "AES-CBC",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );
  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(exportedKey);
}

// Import a base64 string format to its crypto native format
export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const symKey = await webcrypto.subtle.importKey(
    "raw",
    keyBuffer,
    {
      name: "AES-CBC",
      length: 256 
    },
    true,
    ["encrypt", "decrypt"] 
  );
  return symKey;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  const encoder = new TextEncoder();
  const encodeddata = encoder.encode(data);

  const iv = new Uint8Array(16);

  const dataencrypt = await webcrypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv : iv
    },
    key,
    encodeddata,
  );
  return arrayBufferToBase64(dataencrypt);
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {

  const iv = new Uint8Array(16);

  const StrKey = await importSymKey(strKey)
  const datadecrypt = await webcrypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv : iv
    },
    StrKey,
    base64ToArrayBuffer(encryptedData),
  );

  const decoder = new TextDecoder();
  return decoder.decode(datadecrypt);
}