/**
 * Unit tests for `validateArtifacts` in apps/web/src/assessments.ts
 * (L0 — docs/18 Phase 1).
 *
 * Only the pure validator is exercised here; `runArtifactAssessment` talks to
 * both the detection service and Postgres and belongs in the integration suite,
 * the same split as the rest of this repo.
 *
 * Why this validator earns its own tests: the body it guards arrives from a CI
 * runner rather than from the dashboard, so it is the one assessment input that
 * is machine-generated, unattended, and outside our control. Every rejection
 * below is either an identity we cannot file a finding against or a body shaped
 * to make the engine do unbounded work.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { validateArtifacts, type ArtifactManifestIn } from "../apps/web/src/assessments.js";

const SHA = "a".repeat(64);

function manifest(over: Partial<ArtifactManifestIn> = {}): ArtifactManifestIn {
  return { path: "model.pt", sha256: SHA, format: "torch_zip", ...over };
}

describe("validateArtifacts", () => {
  test("accepts a well-formed manifest", () => {
    assert.equal(validateArtifacts([manifest()]), null);
  });

  test("accepts a manifest with no findings-bearing fields at all", () => {
    // A clean safetensors file carries a digest and nothing else. That is a
    // valid scan, not a malformed request.
    assert.equal(validateArtifacts([{ sha256: SHA }]), null);
  });

  test("rejects a missing or empty list", () => {
    assert.match(String(validateArtifacts(undefined)), /artifacts required/);
    assert.match(String(validateArtifacts([])), /artifacts required/);
  });

  test("rejects more than 100 artifacts", () => {
    const many = Array.from({ length: 101 }, () => manifest());
    assert.match(String(validateArtifacts(many)), /at most 100 artifacts/);
    assert.equal(validateArtifacts(Array.from({ length: 100 }, () => manifest())), null);
  });

  describe("the digest is the artifact's identity", () => {
    // A finding is *about* a specific artifact, and the Phase-2 ledger will key
    // on this column. A manifest without a usable digest is not something we can
    // file a finding against, so it is refused rather than stored anonymously.
    test("rejects a missing digest", () => {
      assert.match(String(validateArtifacts([{ path: "m.pt" }])), /sha256/);
    });

    test("rejects a non-hex digest", () => {
      assert.match(String(validateArtifacts([manifest({ sha256: "z".repeat(64) })])), /sha256/);
    });

    test("rejects a wrong-length digest", () => {
      assert.match(String(validateArtifacts([manifest({ sha256: "abc" })])), /sha256/);
      assert.match(String(validateArtifacts([manifest({ sha256: "a".repeat(65) })])), /sha256/);
    });

    test("rejects an uppercase digest rather than normalising it", () => {
      // Storing the same artifact under two spellings would split its history
      // and make digest drift undetectable — the exact thing ARG-ART-013 exists
      // to catch. The CLI emits lowercase; anything else is a different client
      // that should be fixed rather than quietly accommodated.
      assert.match(String(validateArtifacts([manifest({ sha256: "A".repeat(64) })])), /sha256/);
    });

    test("rejects a non-string digest", () => {
      const bad = { sha256: 12345 } as unknown as ArtifactManifestIn;
      assert.match(String(validateArtifacts([bad])), /sha256/);
    });
  });

  describe("bounded work", () => {
    test("rejects an absurd number of globals", () => {
      const globals = Array.from({ length: 20_001 }, () => ({ module: "os", name: "system" }));
      assert.match(String(validateArtifacts([manifest({ globals })])), /at most .* globals/);
    });

    test("rejects an absurd number of archive members", () => {
      const members = Array.from({ length: 20_001 }, (_, i) => ({ name: `m${i}` }));
      assert.match(
        String(validateArtifacts([manifest({ archive_members: members })])),
        /at most .* archive members/,
      );
    });

    test("the caps are generous against a real checkpoint", () => {
      // A torch state_dict resolves a few dozen globals; a sharded model has a
      // few hundred members. The caps must never be the thing that blocks a
      // legitimate scan.
      const globals = Array.from({ length: 500 }, () => ({ module: "torch._utils", name: "x" }));
      const members = Array.from({ length: 500 }, (_, i) => ({ name: `archive/data/${i}` }));
      assert.equal(validateArtifacts([manifest({ globals, archive_members: members })]), null);
    });
  });

  test("rejects a null entry without throwing", () => {
    const bad = [null] as unknown as ArtifactManifestIn[];
    assert.match(String(validateArtifacts(bad)), /must be an object/);
  });

  test("reports the first problem across a mixed batch", () => {
    assert.match(String(validateArtifacts([manifest(), { path: "no-digest.pt" }])), /sha256/);
  });
});
