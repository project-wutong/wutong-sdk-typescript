// SPDX-License-Identifier: AGPL-3.0-only
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const wt = require("../dist/index.js");

const SIG = JSON.parse(fs.readFileSync(path.join(__dirname, "signatures.json"), "utf8"));
const auth = { signerId: SIG.signer_id, keyId: SIG.key_id, issuedAt: SIG.issued_at, nonce: SIG.nonce };
const pub = wt.publicKeyHex(SIG.seed_hex);
const hex = (u8) => Buffer.from(u8).toString("hex");

for (const c of SIG.cases) {
  test(`vector ${c.name}`, () => {
    const ex = JSON.stringify(c.example);
    assert.equal(wt.canonicalize(ex), c.jcs_unsigned_example);
    assert.equal(wt.digest(Buffer.from(c.jcs_unsigned_example)), c.jcs_sha256);
    assert.equal(hex(wt.toDcbor(ex)), c.dcbor_hex_example);
    if (c.name !== "sync_frame") assert.equal(wt.validate(ex), c.kind); // see wutong-protocol needs-decision issue
    const signed = wt.sign(ex, SIG.seed_hex, auth);
    assert.equal(signed, wt.canonicalize(JSON.stringify(c.signed_jcs)));
    assert.match(wt.verify(signed, pub), /^sha256:/);
  });
}

test("strict JSON is enforced", () => {
  for (const bad of ['{"a":1,"a":2}', '{"x":1.5}', '{"x":9007199254740992}']) {
    assert.throws(() => wt.canonicalize(bad), (e) => e instanceof wt.WtpError && e.code === "ERR_SCHEMA");
  }
});

test("tampering breaks the signature", () => {
  const env = { ...SIG.cases[0].signed_jcs, occurred_at: "2026-10-18T10:00:01Z" };
  assert.throws(() => wt.verify(JSON.stringify(env), pub), (e) => e.code === "ERR_SIGNATURE");
});
