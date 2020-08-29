import { join } from "path";
import { existsSync, mkdirSync, rmdirSync } from "fs";
import { KeyObject } from "crypto";
import { config } from "dotenv";

import cryptokit from "../../index";

config({ path: join(__dirname, "..", ".env") });

const folderpath = join(__dirname, "..", "keys", "ephemeral", "P256");
if (!existsSync(folderpath)) {
  mkdirSync(folderpath, { recursive: true });
}

const privateKeyPath = join(folderpath, "private.key");
const publicKeyPath = join(folderpath, "public.key");

describe("P256 keys", () => {
  test("P256 key generation", () => {
    expect(cryptokit.P256.generateKeys(folderpath).privateKeyPath).toStrictEqual(privateKeyPath);
  });

  test("P256 private key loading", () => {
    expect(cryptokit.P256.loadPrivateKey(privateKeyPath)).toEqual(expect.any(KeyObject));
  });

  test("P256 public key loading", () => {
    expect(cryptokit.P256.loadPublicKey(publicKeyPath).object).toEqual(expect.any(KeyObject));
  });
});

rmdirSync(folderpath, { recursive: true });
