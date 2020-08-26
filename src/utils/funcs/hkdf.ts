import { createHmac } from "crypto";

const hashLength = (hash: string) => {
  switch (hash) {
    case "sha256":
      return 32;
    case "sha512":
      return 64;
    case "sha224":
      return 28;
    case "sha384":
      return 48;
    case "sha3-256":
      return 32;
    case "sha3-512":
      return 64;
    case "sha3-224":
      return 28;
    case "sha3-384":
      return 48;
    case "blake2s256":
      return 32;
    case "blake2b512":
      return 64;
    default: {
      // "sha1"
      return 20;
    }
  }
};

function hkdfExtract(hash: string, hashLen: number, ikm: Buffer | string, salt: Buffer | string) {
  const bIkm = Buffer.isBuffer(ikm) ? ikm : Buffer.from(ikm);
  const bSalt = salt && salt.length ? Buffer.from(salt) : Buffer.alloc(hashLen, 0);

  return createHmac(hash, bSalt).update(bIkm).digest();
}

function hkdfExpand(hash: string, hashLen: number, prk: Buffer | string, length: number, info: Buffer | string) {
  const bInfo = Buffer.from(info || "");
  const infoLen = bInfo.length;

  const steps = Math.ceil(length / hashLen);

  if (steps > 0xff) {
    throw new Error(`OKM length ${length} is too long for ${hash} hash`);
  }

  // use single buffer with unnecessary create/copy/move operations
  const t = Buffer.alloc(hashLen * steps + infoLen + 1);

  for (let c = 1, start = 0, end = 0; c <= steps; ++c) {
    // add info
    bInfo.copy(t, end);
    // add counter
    t[end + infoLen] = c;

    createHmac(hash, prk)
      // use view: T(C) = T(C-1) | info | C
      .update(t.slice(start, end + infoLen + 1))
      .digest()
      // put back to the same buffer
      .copy(t, end);

    start = end; // used for T(C-1) start
    end += hashLen; // used for T(C-1) end & overall end
  }

  return t.slice(0, length);
}

export function hkdf(
  ikm: Buffer | string,
  length: number,
  { salt = Buffer.from(""), info = "", hash = "SHA-256" } = {}
) {
  hash = hash.toLowerCase().replace("-", "");
  const hashLen = hashLength(hash);
  const prk = hkdfExtract(hash, hashLen, ikm, salt);
  return hkdfExpand(hash, hashLen, prk, length, info);
}
