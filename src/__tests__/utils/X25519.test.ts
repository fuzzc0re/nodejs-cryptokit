import { join } from "path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { KeyObject } from "crypto";
import { config } from "dotenv";

import cryptokit from "../../index";

config({ path: join(__dirname, "..", ".env") });

const folderpath = join(__dirname, "..", "keys", "ephemeral", "X25519");
if (!existsSync(folderpath)) {
  mkdirSync(folderpath, { recursive: true });
}

const privateKeyPath = join(folderpath, "private.key");
const publicKeyPath = join(folderpath, "public.key");

describe("X25519 keys", () => {
  test("X25519 key generation", async () => {
    const { publicKey, privateKey } = await cryptokit.X25519.generateKeys();
    writeFileSync(publicKeyPath, publicKey);
    writeFileSync(privateKeyPath, privateKey);
    expect(privateKey).toEqual(expect.any(String));
  });

  test("X25519 private key loading", async () => {
    const privateKeyContent = readFileSync(privateKeyPath, "utf8");
    expect(await cryptokit.X25519.loadPrivateKey(privateKeyContent)).toEqual(expect.any(KeyObject));
  });

  test("X25519 public key loading", async () => {
    const publicKeyContent = readFileSync(publicKeyPath, "utf8");
    expect(await cryptokit.X25519.loadPublicKey(publicKeyContent)).toEqual(expect.any(KeyObject));
  });
});
