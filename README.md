# runtimeatlas

## Overview

**runtimeatlas** is a curated knowledge hub focused on understanding and analyzing **system and program behavior during execution** across multiple cybersecurity domains.

Rather than treating offensive, defensive, and forensic disciplines as separate silos, this repository organizes knowledge around a shared reality:

> **Security-relevant outcomes emerge when software is running.**

---

## Core Perspective

In cybersecurity, nearly everything ultimately reduces to **program execution**:

- Attacks succeed because code executes in unintended ways  
- Defenses detect, constrain, or log behavior while systems are running  
- Forensics reconstructs what executed and how  
- Reverse engineering explains why execution behaved as observed  

This repository documents concepts, methodologies, and mental models that help explain **what systems do at runtime**, not just how they are designed or configured.

---

## Scope and Intent

This repository is intended to:

- Capture **conceptual understanding**, not lab walkthroughs  
- Emphasize **execution-time behavior** over static configuration  
- Provide **indexes and synthesis** across domains  
- Serve as a long-term **professional and research-oriented reference**

It is **not** intended to:

- Reproduce proprietary course materials  
- Publish step-by-step exploitation guides  
- Share environment-specific commands, binaries, or answers  

All content is written in original language and generalized beyond specific training environments.

---

## Domains Represented

Content in this repository spans and connects:

- Incident response and detection  
- Network and memory forensics  
- Reverse engineering and malware analysis  
- Binary exploitation and offensive foundations  

These domains are treated as **different viewpoints on the same runtime phenomena**, rather than isolated skill sets.

---

## Organization

The repository is structured primarily by **certification context** for clarity, while remaining unified through shared indexes and runtime-centric analysis.

```text
runtimeatlas/
├── index/          # Cross-domain and runtime-focused indexes
├── gcih/           # Incident response perspectives
├── gnfa/           # Forensics and artifact analysis
├── grem/           # Reverse engineering and program internals
├── gxpn/           # Exploitation and execution control
├── oscp/           # Offensive foundations
└── meta/           # Ethics, scope, and disclosure
