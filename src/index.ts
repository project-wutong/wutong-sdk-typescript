// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Wutong Protocol SDK for TypeScript. Every rule runs in the Rust core compiled to
 * WebAssembly, so results are byte-identical to the Rust, C++, Python and Go SDKs.
 */
// eslint-disable-next-line @typescript-eslint/no-require-imports
const native = require("../pkg/wutong_wasm.js");

export const PROTOCOL = "wutong/0.1";

/** A protocol error; `code` is the normative WTP code, e.g. `ERR_SCHEMA`. */
export class WtpError extends Error {
  readonly code: string;
  constructor(message: string) {
    super(message);
    this.name = "WtpError";
    const i = message.indexOf(":");
    this.code = i > 0 ? message.slice(0, i) : "ERR_INTERNAL";
  }
}

function call<T>(f: () => T): T {
  try {
    return f();
  } catch (e) {
    throw new WtpError(e instanceof Error ? e.message : String(e));
  }
}

export interface Auth {
  signerId: string;
  keyId: string;
  issuedAt: string;
  nonce: string;
}

export const implementation = (): string => native.implementation();
export const canonicalize = (json: string): string => call(() => native.canonicalize(json));
export const toDcbor = (json: string): Uint8Array => call(() => native.toDcbor(json));
export const digest = (data: Uint8Array): string => native.digest(data);
export const validate = (json: string): string => call(() => native.validate(json));
export const publicKeyHex = (seedHex: string): string => call(() => native.publicKeyHex(seedHex));
export const sign = (json: string, seedHex: string, a: Auth): string =>
  call(() => native.sign(json, seedHex, a.signerId, a.keyId, a.issuedAt, a.nonce));
export const verify = (json: string, publicKey: string): string => call(() => native.verify(json, publicKey));
