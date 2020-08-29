import { join } from "path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import {
  randomBytes,
  createHash,
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  createPrivateKey,
  KeyObject,
} from "crypto";

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

  return { privateKeyPath, publicKeyPath };
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

// To convert iOS public keys to PEM
const curve25519OIDHeaderLen = 12;
const X25519OIDHeader = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
export const X25519ASNBuffer = Buffer.from(X25519OIDHeader, curve25519OIDHeaderLen);

export function loadX25519PublicKey(filepath: string): { object: KeyObject; raw: string } {
  const content = readFileSync(filepath, "utf8");
  const publicKeyObject = createPublicKey({ key: content });

  const rawWithHeader = publicKeyObject.export({ type: "spki", format: "der" });
  const rawWithoutHeader = rawWithHeader.slice(curve25519OIDHeaderLen);

  return { object: publicKeyObject, raw: rawWithoutHeader.toString("base64") };
}
