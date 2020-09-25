import { join } from "path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
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
  test("P256 key generation", async () => {
    const { publicKey, privateKey } = await cryptokit.P256.generateKeys();

    const P256PublicKey = await cryptokit.P256.loadPublicKey(publicKey);
    const rawP256PublicKey = await cryptokit.P256.formatPublicKeyToRaw(P256PublicKey);
    console.log("Raw P256 public key to copy to iOS = " + rawP256PublicKey);

    writeFileSync(publicKeyPath, publicKey);
    writeFileSync(privateKeyPath, privateKey);
    expect(privateKey).toEqual(expect.any(String));
  });

  test("P256 private key loading", async () => {
    const privateKeyContent = readFileSync(privateKeyPath, "utf8");
    expect(await cryptokit.P256.loadPrivateKey(privateKeyContent)).toEqual(expect.any(KeyObject));
  });

  test("P256 public key loading", async () => {
    const publicKeyContent = readFileSync(publicKeyPath, "utf8");
    expect(await cryptokit.P256.loadPublicKey(publicKeyContent)).toEqual(expect.any(KeyObject));
  });
});
