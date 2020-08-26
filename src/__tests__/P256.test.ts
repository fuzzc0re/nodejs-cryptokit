import { join } from "path";
import { existsSync, mkdirSync, rmdirSync } from "fs";
import { KeyObject } from "crypto";
import { config } from "dotenv";

import { generateP256Keys, loadP256PrivateKeyObject, loadP256PublicKeyObject } from "../utils/P256";

config({ path: join(__dirname, ".env") });

const folderpath = join(__dirname, "keys", "ephemeral", "P256");
if (!existsSync(folderpath)) {
  mkdirSync(folderpath, { recursive: true });
}

const privateKeyPath = join(folderpath, "private.key");
const publicKeyPath = join(folderpath, "public.key");

describe("P256 keys", () => {
  test("P256 key generation", () => {
    expect(generateP256Keys(folderpath).privateKeyPath).toStrictEqual(privateKeyPath);
  });

  test("P256 private key loading", () => {
    expect(loadP256PrivateKeyObject(privateKeyPath)).toEqual(expect.any(KeyObject));
  });

  test("P256 public key loading", () => {
    expect(loadP256PublicKeyObject(publicKeyPath)).toEqual(expect.any(KeyObject));
  });
});

rmdirSync(folderpath, { recursive: true });
