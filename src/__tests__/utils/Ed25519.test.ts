import { join } from "path";
import { existsSync, mkdirSync, rmdirSync } from "fs";
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
  test("Ed25519 key generation", () => {
    expect(cryptokit.Ed25519.generateKeys(folderpath).privateKeyPath).toStrictEqual(privateKeyPath);
  });

  test("Ed25519 private key loading", () => {
    expect(cryptokit.Ed25519.loadPrivateKey(privateKeyPath)).toEqual(expect.any(KeyObject));
  });

  test("Ed25519 public key loading", () => {
    expect(cryptokit.Ed25519.loadPublicKey(publicKeyPath).object).toEqual(expect.any(KeyObject));
  });
});

rmdirSync(folderpath, { recursive: true });
