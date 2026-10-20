// SPDX-License-Identifier: AGPL-3.0-only
//! wasm-bindgen surface. Errors are thrown as JS `Error("ERR_X: detail")`; the TypeScript
//! wrapper turns them into typed `WtpError`s.

use wasm_bindgen::prelude::*;
use wutong_core::crypto::{self, Encoding, Mode, SignParams, VerifyOptions};
use wutong_core::types::WtpError;
use wutong_core::wire::{dcbor, jcs, sha256_digest, strict};

fn js(e: WtpError) -> JsError {
    JsError::new(&format!("{}: {}", e.code.as_str(), e.detail))
}

fn utf8(b: Vec<u8>) -> String {
    String::from_utf8(b).expect("canonical JSON is UTF-8")
}

/// Implementation string of the Rust core.
#[wasm_bindgen]
pub fn implementation() -> String {
    wutong_core::IMPLEMENTATION.to_string()
}

/// Strictly parse JSON and return its RFC 8785 canonical form.
#[wasm_bindgen]
pub fn canonicalize(json: &str) -> Result<String, JsError> {
    let v = strict::parse(json.as_bytes()).map_err(js)?;
    Ok(utf8(jcs::canonicalize(&v).map_err(js)?))
}

/// Deterministic CBOR encoding of strict JSON.
#[wasm_bindgen(js_name = toDcbor)]
pub fn to_dcbor(json: &str) -> Result<Vec<u8>, JsError> {
    let v = strict::parse(json.as_bytes()).map_err(js)?;
    dcbor::encode(&v).map_err(js)
}

/// `sha256:<hex>` of the exact bytes.
#[wasm_bindgen]
pub fn digest(data: &[u8]) -> String {
    sha256_digest(data).to_string()
}

/// Strict parse + schema + semantic validation; returns the message kind.
#[wasm_bindgen]
pub fn validate(json: &str) -> Result<String, JsError> {
    let env = wutong_core::parse_and_validate(json.as_bytes()).map_err(js)?;
    Ok(env.kind().as_str().to_string())
}

fn seed(hex_seed: &str) -> Result<[u8; 32], JsError> {
    hex::decode(hex_seed)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| JsError::new("seed must be 64 hex characters"))
}

/// Ed25519 public key (hex) of a hex seed.
#[wasm_bindgen(js_name = publicKeyHex)]
pub fn public_key_hex(seed_hex: &str) -> Result<String, JsError> {
    let k = crypto::signing_key_from_seed(&seed(seed_hex)?);
    Ok(hex::encode(k.verifying_key().to_bytes()))
}

/// Sign an unsigned envelope (JCS signing input); returns the signed envelope as JCS.
#[wasm_bindgen]
pub fn sign(
    json: &str,
    seed_hex: &str,
    signer_id: &str,
    key_id: &str,
    issued_at: &str,
    nonce: &str,
) -> Result<String, JsError> {
    let v = strict::parse(json.as_bytes()).map_err(js)?;
    let key = crypto::signing_key_from_seed(&seed(seed_hex)?);
    let p = SignParams {
        signer_id,
        key_id,
        issued_at,
        nonce,
        encoding: Encoding::Jcs,
        include_encoding: false,
    };
    let s = crypto::sign_envelope(&v, &key, &p).map_err(js)?;
    Ok(utf8(jcs::canonicalize(&s).map_err(js)?))
}

/// Verify a signed envelope (archive mode) against a hex public key; returns its digest.
#[wasm_bindgen]
pub fn verify(json: &str, public_key_hex: &str) -> Result<String, JsError> {
    let pk = crypto::validate_public_key_hex(public_key_hex).map_err(js)?;
    let vk = crypto::verifying_key(&pk).map_err(js)?;
    let lookup = move |_: &str, _: &str| Some(vk);
    let v = strict::parse(json.as_bytes()).map_err(js)?;
    let opts = VerifyOptions {
        mode: Mode::Archive,
        ..Default::default()
    };
    crypto::verify_envelope(&v, &lookup, opts).map_err(js)
}
