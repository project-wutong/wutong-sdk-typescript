# Wutong SDK for TypeScript · 梧桐 TypeScript SDK

[![CI](https://github.com/project-wutong/wutong-sdk-typescript/actions/workflows/ci.yml/badge.svg)](https://github.com/project-wutong/wutong-sdk-typescript/actions/workflows/ci.yml)
Node ≥ 20 · Rust core compiled to WebAssembly · `AGPL-3.0-only`

## 中文

TypeScript/JavaScript SDK：协议逻辑来自编译为 WebAssembly 的 Rust [`wutong-core`](https://github.com/project-wutong/wutong-core)，
TypeScript 层只负责类型与错误包装（`WtpError.code`）。当前产物面向 Node（`wasm-pack --target nodejs`），
浏览器/打包器目标在后续里程碑提供。

```bash
npm ci && npm run build && npm test
```

```ts
import { validate, sign, verify } from "@project-wutong/wutong";
validate(json);                       // "wutong.principal"
const signed = sign(json, seedHex, { signerId, keyId, issuedAt, nonce });
verify(signed, publicKeyHex);         // "sha256:…"
```

## English

`wasm/` is a thin `wasm-bindgen` crate over `wutong-core`; `src/index.ts` adds types and typed
errors. Tests replay all 24 cross-language signature vectors from `wutong-protocol`.
