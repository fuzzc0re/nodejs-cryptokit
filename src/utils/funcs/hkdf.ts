import { createHmac } from "crypto";

function getHashLength(hash: "sha256" | "sha384" | "sha512") {
  switch (hash) {
    case "sha256":
      return 32;
    case "sha384":
      return 48;
    default: {
      // "sha512"
      return 64;
    }
  }
}

function extract(
  hash: "sha256" | "sha384" | "sha512",
  hashLength: 32 | 48 | 64,
  ikm: string | Buffer,
  salt: string | Buffer
) {
  const ikmBuffer = Buffer.isBuffer(ikm) ? ikm : Buffer.from(ikm);
  const saltBuffer = salt && salt.length ? Buffer.from(salt) : Buffer.alloc(hashLength, 0);

  return createHmac(hash, saltBuffer).update(ikmBuffer).digest();
}

function expand(
  hash: "sha256" | "sha384" | "sha512",
  hashLength: 32 | 48 | 64,
  prk: string | Buffer,
  length: number,
  info: string | Buffer
) {
  const infoBuffer = Buffer.from(info || "");
  const infoLength = infoBuffer.length;
  const steps = Math.ceil(length / hashLength);

  if (steps > 0xff) {
    throw new Error(`OKM length ${length} is too long for ${hash} hash`);
  }

  const t = Buffer.alloc(hashLength * steps + infoLength + 1);

  for (let counter = 1, start = 0, end = 0; counter <= steps; ++counter) {
    infoBuffer.copy(t, end);
    t[end + infoLength] = counter;

    createHmac(hash, prk)
      .update(t.slice(start, end + infoLength + 1))
      .digest()
      .copy(t, end);

    start = end;
    end += hashLength;
  }

  return t.slice(0, length);
}

export function hkdf(
  ikm: string | Buffer,
  length: number,
  salt: Buffer,
  info = "",
  hash: "sha256" | "sha384" | "sha512" = "sha512"
) {
  const hashLength = getHashLength(hash);
  const prk = extract(hash, hashLength, ikm, salt);

  return expand(hash, hashLength, prk, length, info);
}
