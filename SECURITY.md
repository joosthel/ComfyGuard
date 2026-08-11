# Security policy

ComfyGuard is a security tool, so its own security matters. This policy covers
vulnerabilities in ComfyGuard itself.

## Reporting a vulnerability

Please report privately, not in a public issue.

- Preferred: use GitHub's private vulnerability reporting on this repository
  (the **Security** tab, then **Report a vulnerability**).
- Alternatively, contact the maintainer (@joosthel) privately.

Include what you found, how to reproduce it, and the impact. We aim to acknowledge
a report within a few days and to keep you updated as we work on a fix. Please give
us reasonable time to address the issue before any public disclosure.

## Scope

In scope is anything in this repository: the scanner and its logic, the report
handling, the ruleset, and the agent skills. Because ComfyGuard is strictly
read-only by design, the issues we care most about are:

- A path where the tool could change a scanned instance at all (it must only ever
  write its own report artifacts).
- A path where scanning a hostile target (a crafted node, model, or workflow)
  could execute code, read data outside the scan, or exfiltrate anything from the
  host running ComfyGuard.
- Secret values leaking into a report (it is designed to record names and
  locations only, never secret values).

## Out of scope

- Vulnerabilities in **ComfyUI itself** or in **ComfyUI-Manager**. Report those to
  their maintainers through the ComfyUI security process. ComfyGuard reports on
  such issues but does not fix them.
- Vulnerabilities in third-party custom nodes. Report those to the node's author.
- A clean grade or a missed finding. ComfyGuard does not claim to prove an instance
  is safe; a missed detection is a bug or a feature request, not a vulnerability in
  ComfyGuard.

## Responsible use

ComfyGuard is a defensive self-assessment tool. Use it only against ComfyUI
deployments you operate or are authorized to test. The active network probe is
opt-in, defaults to localhost, and requires you to assert authorization for any
non-loopback target.
