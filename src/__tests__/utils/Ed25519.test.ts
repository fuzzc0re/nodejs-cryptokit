import { join } from "path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { KeyObject } from "crypto";
import { config } from "dotenv";

import cryptokit from "../../index";

config({ path: join(__dirname, "..", ".env") });

const folderpath = join(__dirname, "..", "keys", "ephemeral", "Ed25519");
if (!existsSync(folderpath)) {
  mkdirSync(folderpath, { recursive: true });
}

const privateKeyPath = join(folderpath, "private.key");
const publicKeyPath = join(folderpath, "public.key");

describe("Ed25519 keys", () => {
  test("Ed25519 key generation", async () => {
    const { publicKey, privateKey } = await cryptokit.Ed25519.generateKeys();
    writeFileSync(publicKeyPath, publicKey);
    writeFileSync(privateKeyPath, privateKey);
    expect(privateKey).toEqual(expect.any(String));
  });

  test("Ed25519 private key loading", async () => {
    const privateKeyContent = readFileSync(privateKeyPath, "utf8");
    expect(await cryptokit.Ed25519.loadPrivateKey(privateKeyContent)).toEqual(expect.any(KeyObject));
  });

  test("Ed25519 public key loading", async () => {
    const publicKeyContent = readFileSync(publicKeyPath, "utf8");
    expect(await cryptokit.Ed25519.loadPublicKey(publicKeyContent)).toEqual(expect.any(KeyObject));
  });
});
