import { join } from "path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { randomBytes, createHash, createCipheriv, createDecipheriv, createPublicKey, createPrivateKey } from "crypto";
import { execSync } from "child_process";

import { generateX25519 } from "./funcs/generateX25519";

const hash = "sha512";
const algorithm = "aes-256-ctr";

export function generateX25519Keys(folderpath: string) {
  if (!existsSync(folderpath)) {
    mkdirSync(folderpath, { recursive: true });
  }

  const iv = randomBytes(16).toString("hex").slice(0, 16);
  const pass = createHash(hash)
    .update(Buffer.from(process.env.X25519_PASS as string))
    .digest("base64")
    .substr(0, 32);

  const { publicKey, privateKey } = generateX25519();

  const privateKeyBuffer = Buffer.from(privateKey, "utf8");
  const cipher = createCipheriv(algorithm, pass, iv);
  const privateKeyCipherBuffer = cipher.update(privateKeyBuffer);
  const privateKeyBufferFinal = Buffer.concat([privateKeyCipherBuffer, cipher.final()]);

  const privateKeyPath = join(folderpath, "private.key");
  const publicKeyPath = join(folderpath, "public.key");

  writeFileSync(privateKeyPath, iv + ":" + privateKeyBufferFinal.toString("base64"));
  writeFileSync(publicKeyPath, publicKey);
  const asn1parse = execSync("openssl asn1parse -in " + publicKeyPath + " -dump").toString();

  return { privateKeyPath, publicKeyPath, asn1parse };
}

export function loadX25519PrivateKeyObject(filepath: string) {
  const privateKeyPass = createHash("sha512")
    .update(Buffer.from(process.env.X25519_PASS as string))
    .digest("base64")
    .substr(0, 32);
  const privateKeyFileContent = readFileSync(filepath, "utf8");
  const privateKeyFileContentParts = privateKeyFileContent.split(":");
  const privateKeyDecryptionIv = privateKeyFileContentParts.shift();
  const privateKeyFileContentKey = privateKeyFileContentParts.join(":");
  const privateKeyEncrypted = Buffer.from(privateKeyFileContentKey, "base64");
  const privateKeyDecipher = createDecipheriv(algorithm, privateKeyPass, privateKeyDecryptionIv as string);
  const privateKeyDeciphered = privateKeyDecipher.update(privateKeyEncrypted);
  const privateKey = Buffer.concat([privateKeyDeciphered, privateKeyDecipher.final()]);
  const privateKeyObject = createPrivateKey({
    key: privateKey,
  });

  return privateKeyObject;
}

export function loadX25519PublicKeyObject(filepath: string) {
  const publicKeyFileContent = readFileSync(filepath, "utf8");
  const publicKeyObject = createPublicKey({ key: publicKeyFileContent });

  return publicKeyObject;
}

// To convert iOS public keys to PEM
const curve25519OIDHeaderLen = 12;
const X25519OIDHeader = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
export const X25519ASNBuffer = Buffer.from(X25519OIDHeader, curve25519OIDHeaderLen);