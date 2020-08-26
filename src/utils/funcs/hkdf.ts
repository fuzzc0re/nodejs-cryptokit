import { createHmac } from "crypto";

const hash_length = (hash: string) => {
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

function hkdf_extract(hash: string, hash_len: number, ikm: Buffer | string, salt: Buffer | string) {
  const b_ikm = Buffer.isBuffer(ikm) ? ikm : Buffer.from(ikm);
  const b_salt = salt && salt.length ? Buffer.from(salt) : Buffer.alloc(hash_len, 0);

  return createHmac(hash, b_salt).update(b_ikm).digest();
}

function hkdf_expand(hash: string, hash_len: number, prk: Buffer | string, length: number, info: Buffer | string) {
  const b_info = Buffer.from(info || "");
  const info_len = b_info.length;

  const steps = Math.ceil(length / hash_len);

  if (steps > 0xff) {
    throw new Error(`OKM length ${length} is too long for ${hash} hash`);
  }

  // use single buffer with unnecessary create/copy/move operations
  const t = Buffer.alloc(hash_len * steps + info_len + 1);

  for (let c = 1, start = 0, end = 0; c <= steps; ++c) {
    // add info
    b_info.copy(t, end);
    // add counter
    t[end + info_len] = c;

    createHmac(hash, prk)
      // use view: T(C) = T(C-1) | info | C
      .update(t.slice(start, end + info_len + 1))
      .digest()
      // put back to the same buffer
      .copy(t, end);

    start = end; // used for T(C-1) start
    end += hash_len; // used for T(C-1) end & overall end
  }

  return t.slice(0, length);
}

export function hkdf(
  ikm: Buffer | string,
  length: number,
  { salt = Buffer.from(""), info = "", hash = "SHA-256" } = {}
) {
  hash = hash.toLowerCase().replace("-", "");
  const hash_len = hash_length(hash);
  const prk = hkdf_extract(hash, hash_len, ikm, salt);
  return hkdf_expand(hash, hash_len, prk, length, info);
}
