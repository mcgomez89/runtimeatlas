# Section 2 — Data Encoding, Cryptographic Controls, and Trust Boundaries

This section examines how data is encoded, transformed, encrypted, and validated, and how assumptions about confidentiality, integrity, and authorization can fail.  
The focus is not on breaking cryptographic algorithms, but on **abusing how cryptography and data handling are applied and trusted**.

Across these labs, control is gained by manipulating cryptographic context, data formatting, and enforcement boundaries rather than defeating encryption primitives.

---

## Lab 2.1 — Differentiating Encryption, Compression, and Obfuscation

### Summary
This lab demonstrates that encrypted, compressed, and obfuscated data can exhibit similar statistical properties. High entropy alone does not prove encryption, and low entropy does not imply plaintext.

The failure occurs when security decisions are made based on **appearance rather than structure and context**.

### Tooling Examples
- **ent**: Measures entropy and randomness to compare transformed data.
- **gzip**: Demonstrates how compression alters entropy without providing confidentiality.
- **pcaphistogram.py**: Visualizes byte distribution to highlight transformation artifacts.
- **gnuplot**: Renders histograms to compare data patterns visually.

### Mitigation Examples
- Combine entropy analysis with payload structure inspection.
- Treat entropy metrics as indicators, not conclusions.
- Analyze protocol framing separately from payload content.

### Where This Leads
Misclassification of data can cause encrypted, compressed, or sensitive traffic to be ignored or mishandled during analysis.

---

## Lab 2.2 — Manipulating Encrypted Data via Cipher Mode Properties

### Summary
This lab demonstrates that certain encryption modes allow controlled manipulation of decrypted data when integrity is not enforced. The cryptography itself remains sound, but the system **trusts unauthenticated decrypted output**.

The failure lies in missing authenticity and validation, not weak encryption.

### Tooling Examples
- **OpenSSL**: Used to identify cipher properties and encryption behavior.
- **Browser-based parameter tampering**: Observes how ciphertext changes affect application behavior.
- **Python**: Performs controlled XOR calculations to reason about transformations.

### Mitigation Examples
- Use authenticated encryption modes (e.g., AEAD).
- Reject modified ciphertext explicitly.
- Validate decrypted values before authorization decisions.

### Where This Leads
Once encrypted data can be predictably manipulated, authorization and logic checks become unreliable.

---

## Lab 2.3 — Extending Trust Through Hash-Based Authorization

### Summary
This lab demonstrates that hashes used as authorization tokens can be abused when their construction is predictable. The system assumes a hash represents fixed intent, when it may only partially bind input.

The failure occurs when **hashes are used for authorization instead of authentication**.

### Tooling Examples
- **hash_extender**: Exploits hash length extension properties.
- **Browser developer tools**: Identify authorization parameters.
- **Traffic inspection utilities**: Observe how hashes are validated server-side.

### Mitigation Examples
- Use HMAC instead of raw hashes.
- Bind authorization tokens to explicit parameters.
- Validate authorization server-side with full context.

### Where This Leads
Authorization bypass enables access to data and resources beyond intended scope.

---

## Lab 2.4 — Escaping Restricted Execution Environments

### Summary
This lab demonstrates that restricted desktops and kiosk environments rely on incomplete assumptions about user interaction paths. Controls focus on blocking applications while ignoring alternate execution vectors.

The failure occurs because **execution surfaces extend beyond intended workflows**.

### Tooling Examples
- **Built-in Windows applications**: Leveraged for indirect execution.
- **Object embedding mechanisms**: Trigger alternate execution contexts.
- **Explorer.exe**: Used to transition from restricted to full desktop contexts.

### Mitigation Examples
- Enforce restrictions at the OS policy level.
- Remove unused application features.
- Monitor unexpected process launches.

### Where This Leads
Once execution is achieved, local restrictions can be bypassed incrementally.

---

## Lab 2.5 — Client-Side Execution and Post-Authentication Abuse

### Summary
This lab demonstrates that client-side execution enables deep access without immediate privilege escalation. User-level execution exposes credentials, session data, and sensitive memory.

The failure lies in **overtrusting authenticated user execution contexts**.

### Tooling Examples
- **PowerShell**: Executes in-memory tooling.
- **Seatbelt**: Enumerates credentials and security posture.
- **winPEAS**: Identifies privilege escalation opportunities.
- **Mimikittenz**: Extracts credentials from process memory.
- **Python HTTP server**: Stages tools through trusted delivery paths.

### Mitigation Examples
- Limit user execution privileges.
- Monitor in-memory PowerShell activity.
- Harden AMSI and script execution policies.

### Where This Leads
Credential exposure and persistence enable lateral movement and long-term access.

---

## Lab 2.6 — Enterprise DLP and Control Bypass

### Summary
This lab demonstrates that enterprise controls often fail under real operational conditions. Security products enforce policy boundaries but cannot fully anticipate legitimate workflows.

The failure occurs when **controls interfere with normal use and must be bypassed to function**.

### Tooling Examples
- **Seatbelt**: Identifies enforcement gaps and credential exposure.
- **PowerUp**: Enumerates escalation opportunities.
- **Empire**: Demonstrates post-exploitation chaining.
- **Mimikatz**: Extracts credentials for lateral movement.

### Mitigation Examples
- Design controls that align with operational reality.
- Test DLP and isolation systems adversarially.
- Monitor behavior, not just policy violations.

### Where This Leads
Once enterprise controls are bypassed, attackers operate indistinguishably from legitimate users.

---

## Section Summary

All labs in this section demonstrate that **cryptographic and data controls fail when context is ignored**.  
Encryption protects data only when integrity, authorization, and usage assumptions are enforced consistently.

When transformed data is trusted blindly, security controls become advisory rather than protective.

---

## Next Steps

With data protections bypassed or misapplied, attackers are no longer constrained by format or confidentiality.  
The next phase focuses on identifying **how input reaches code**, what execution paths are exposed, and how program behavior can be observed and influenced.

This shifts the attacker from **data manipulation** to **execution discovery**, enabling systematic identification of reachable logic and vulnerability conditions.
