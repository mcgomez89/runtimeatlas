# Section 1 — Network Access Control and Bypass

This section examines how access to a network is granted, inferred, or assumed, and how those assumptions can be violated. The focus is not on exploiting software vulnerabilities, but on **gaining or abusing access by manipulating network trust decisions**.

Across these labs, access is achieved by influencing how the network evaluates identity, posture, routing, or session state.

---

## Lab 1.2 — Circumventing Network Admission Checks

### Summary
This lab demonstrates how network admission controls determine access based on observable client characteristics rather than authenticated identity. Access is granted when the device appears compliant, even if that appearance is manipulated.

The control fails because enforcement relies on inference, not proof.

### Tooling Examples
- **Wireshark**: Used to observe health-check traffic and identify what conditions trigger denial.
- **Firefox User-Agent Switcher**: Used to alter browser identity to satisfy client-type checks.
- **Linux network utilities**: Used to modify interface attributes visible to the network.

### Mitigation Examples
- Require authentication before assigning meaningful network access.
- Avoid MAC address–based trust decisions.
- Treat posture checks as supplemental, not authoritative.

### Where This Leads
Once basic network access is achieved, attackers can observe or influence other hosts on the segment.

---

## Lab 1.3 — Gaining Network Position for Credential Exposure

### Summary
This lab demonstrates how being present on the network enables interception and manipulation of authentication traffic. Credentials are exposed not by exploiting the endpoint, but by abusing network trust.

### Tooling Examples
- **Responder**: Captures authentication material exposed over the network.
- **Ettercap**: Establishes a man-in-the-middle position on a switched network.
- **Custom Ettercap filters**: Manipulate HTTP content to induce authentication attempts.

### Mitigation Examples
- Enforce encrypted authentication protocols.
- Avoid implicit trust of local network segments.
- Monitor for ARP poisoning and anomalous name resolution.

### Where This Leads
With credentials or hashes captured, attackers can pivot to authentication or lateral movement.

---

## Lab 1.4 — Bypassing Network Filters via Alternate Protocol Paths

### Summary
This lab demonstrates how access controls applied unevenly across protocol stacks allow restricted services to remain reachable. IPv4 filtering does not imply equivalent IPv6 protection.

### Tooling Examples
- **Nmap**: Used to compare service exposure across IPv4 and IPv6.
- **ip / neighbor discovery utilities**: Used to map address relationships.
- **socat**: Bridges protocol boundaries to relay traffic.

### Mitigation Examples
- Apply consistent filtering across all enabled protocols.
- Disable unused protocol stacks where possible.
- Audit exposure using both IPv4 and IPv6.

### Where This Leads
Once services are reachable, application-level weaknesses become exploitable.

---

## Lab 1.5 — Manipulating Application Content in Transit

### Summary
This lab demonstrates how access to the network path enables modification of application responses when integrity is not enforced. The attacker alters content without compromising the endpoint.

### Tooling Examples
- **mitmproxy / mitmdump**: Performs transparent HTTP response modification.
- **Custom injection scripts**: Insert attacker-controlled content into responses.
- **Lightweight HTTP servers**: Host injected resources.

### Mitigation Examples
- Enforce HTTPS consistently.
- Validate content integrity end-to-end.
- Avoid reliance on network trust for response safety.

### Where This Leads
Control over content enables session manipulation, phishing, and credential capture.

---

## Lab 1.6 — Abusing Routing Trust Relationships

### Summary
This lab demonstrates how routing protocols trust adjacent peers and how joining that trust domain enables traffic redirection. Control-plane access influences data-plane behavior.

### Tooling Examples
- **Wireshark / tcpdump**: Observes routing protocol authentication data.
- **Loki**: Captures, analyzes, and injects routing updates.
- **John the Ripper**: Cracks routing authentication material.

### Mitigation Examples
- Isolate routing protocols from user-accessible networks.
- Use strong, unique routing authentication keys.
- Monitor for unexpected route advertisements.

### Where This Leads
Traffic redirection enables interception, downgrade, or manipulation of downstream services.

---

## Lab 1.7 — Session-Based MFA Bypass Through Network Control

### Summary
This lab demonstrates that MFA protects authentication events, not session continuity. When session artifacts are captured via network access, MFA can be bypassed without breaking the authentication mechanism itself.

### Tooling Examples
- **evilginx**: Acts as a reverse proxy to capture authenticated session tokens.
- **DNS and certificate tooling**: Enables convincing service impersonation.
- **Browser cookie editors**: Reuse captured session artifacts.

### Mitigation Examples
- Bind session tokens to client context and device state.
- Revalidate sessions after MFA events.
- Treat MFA as one component of access control, not a guarantee.

### Where This Leads
With authenticated sessions, attackers transition from access to **post-authentication abuse**.

---

## Section Summary

All labs in this section demonstrate that **network access is the prerequisite control**. When access is granted—intentionally or accidentally—many downstream defenses assume trust that no longer exists.

Authentication, encryption, and MFA are only effective if network access decisions are correct and consistently enforced.

---

## Next Steps

The next section shifts focus from *access* to *data handling*. With access established, attention moves to how data is encoded, encrypted, validated, and transformed—and how failures in those processes enable exploitation.
