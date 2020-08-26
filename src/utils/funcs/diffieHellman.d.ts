import { KeyObject } from "crypto";

declare function dh(publicKey: KeyObject, privateKey: KeyObject): Buffer;
