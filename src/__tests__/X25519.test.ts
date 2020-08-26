import { join } from "path";
import { existsSync, mkdirSync, rmdirSync } from "fs";
import { KeyObject } from "crypto";
import { config } from "dotenv";

import { generateX25519Keys, loadX25519PrivateKeyObject, loadX25519PublicKeyObject } from "../utils/X25519";

config({ path: join(__dirname, ".env") });

const folderpath = join(__dirname, "keys", "ephemeral", "X25519");
if (!existsSync(folderpath)) {
  mkdirSync(folderpath, { recursive: true });
}

const privateKeyPath = join(folderpath, "private.key");
const publicKeyPath = join(folderpath, "public.key");

describe("X25519 keys", () => {
  test("X25519 key generation", () => {
    expect(generateX25519Keys(folderpath)).toStrictEqual({
      privateKeyPath,
      publicKeyPath,
    });
  });

  test("X25519 private key loading", () => {
    expect(loadX25519PrivateKeyObject(privateKeyPath)).toEqual(expect.any(KeyObject));
  });

  test("X25519 public key loading", () => {
    expect(loadX25519PublicKeyObject(publicKeyPath)).toEqual(expect.any(KeyObject));
  });
});

rmdirSync(folderpath, { recursive: true });
