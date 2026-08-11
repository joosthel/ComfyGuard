<!-- Thanks for contributing to ComfyGuard. Keep each PR focused on one change. -->

**What this changes**

A short description, and the issue it addresses (for example `Closes #12`).

**Type**

- [ ] New or updated check / ruleset entry
- [ ] Threat feed entry (CVE or malicious node) with a primary source
- [ ] Documentation
- [ ] Implementation
- [ ] Other

**Checklist**

- [ ] It preserves the read-only principle (every command changes nothing on the
      scanned instance and writes only ComfyGuard's own report artifacts).
- [ ] It does not execute untrusted code or deserialize model files.
- [ ] Docs and examples are updated in the same PR.
- [ ] New checks include a default severity, confidence, remediation class, and a
      primary-source reference, and are written to be low-noise.
- [ ] Writing style matches the docs: direct and concrete, no marketing language.
