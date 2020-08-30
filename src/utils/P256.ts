import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { generateKeyPairSync, createPublicKey, createPrivateKey } from "crypto";
import { join } from "path";

const algorithm = "aes-256-ctr";

export function generateP256Keys(folderpath: string) {
  if (!existsSync(folderpath)) {
    mkdirSync(folderpath, { recursive: true });
  }

  const p256Keys = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "sec1",
      format: "pem",
      cipher: algorithm,
      passphrase: process.env.P256_PASS,
    },
  });

  const privateKeyPath = join(folderpath, "private.key");
  const publicKeyPath = join(folderpath, "public.key");

  writeFileSync(privateKeyPath, p256Keys.privateKey);
  writeFileSync(publicKeyPath, p256Keys.publicKey);

  return { privateKeyPath, publicKeyPath };
}

export function loadP256PrivateKey(filepath: string) {
  const content = readFileSync(filepath, "utf8");
  const privateKeyObject = createPrivateKey({
    key: content,
    type: "sec1",
    format: "pem",
    passphrase: process.env.P256_PASS,
  });

  return privateKeyObject;
}

// To convert iOS public keys to PEM
const P256OIDHeader = new Uint8Array([
  0x30,
  0x59,
  0x30,
  0x13,
  0x06,
  0x07,
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x02,
  0x01,
  0x06,
  0x08,
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x03,
  0x01,
  0x07,
  0x03,
  0x42,
  0x00,
]);
const P256OIDHeaderLen = 26;
export const P256ASNBuffer = Buffer.from(P256OIDHeader, P256OIDHeaderLen);

export function loadP256PublicKey(filepath: string) {
  const content = readFileSync(filepath, "utf8");
  const publicKeyObject = createPublicKey({ key: content });

  return publicKeyObject;
}
