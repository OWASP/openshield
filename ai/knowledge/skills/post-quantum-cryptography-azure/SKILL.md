---
name: post-quantum-cryptography-azure
description: Identifies and remediates non-quantum-safe cryptographic configurations in Azure including classical TLS key exchange, RSA and ECC keys in Key Vault, and classical certificate algorithms. Maps findings to NIST PQC standards FIPS 203, FIPS 204, and FIPS 205. Use when assessing quantum readiness of Azure infrastructure or building a Cryptographic Bill of Materials.
domain: cybersecurity
subdomain: post-quantum-cryptography
tags:
- post-quantum
- pqc
- azure
- key-vault
- tls
- cryptography
- cbom
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.DS-1
- PR.DS-2
- PR.AC-4
---

# Post-Quantum Cryptography Assessment for Azure

## When to Use
- When assessing an Azure environment for quantum readiness
- When building a Cryptographic Bill of Materials for Azure resources
- When identifying classical cryptographic algorithms that need migration
- When planning post-quantum migration for Key Vault keys and certificates
- When evaluating TLS configurations for quantum vulnerability

## Key Concepts

| Term | Definition |
|------|------------|
| Harvest Now Decrypt Later | Attack where adversaries collect encrypted traffic today and decrypt it when quantum computers become available |
| Shor's Algorithm | Quantum algorithm that can break RSA and ECC by solving integer factorisation and discrete logarithm problems efficiently |
| ML-KEM | Module Lattice Key Encapsulation Mechanism, NIST FIPS 203, post-quantum safe key exchange |
| ML-DSA | Module Lattice Digital Signature Algorithm, NIST FIPS 204, post-quantum safe signing |
| SLH-DSA | Stateless Hash-Based Digital Signature Algorithm, NIST FIPS 205, post-quantum safe signing |
| CBOM | Cryptographic Bill of Materials, inventory of all cryptographic assets in a system |
| PQMA | Post-Quantum Migration Analyser, tool for validating PQC migration paths |

## OpenShield PQC Rules

| Rule | Description | Severity |
|------|-------------|----------|
| AZ-PQC-001 | TLS below 1.3 on App Service | HIGH |
| AZ-PQC-002 | Key Vault key using RSA or ECC algorithm | HIGH |
| AZ-PQC-003 | Key Vault certificate using non-quantum-safe signature algorithm | MEDIUM |

## Assessment Workflow

### Step 1: Identify Classical Keys in Key Vault
```bash
az keyvault list --output table
az keyvault key list --vault-name <vault-name> --output table
az keyvault certificate list --vault-name <vault-name> --output table
```

### Step 2: Check TLS Configuration on App Services
```bash
az webapp list --output table
az webapp config show --resource-group <rg> --name <app-name> --query minTlsVersion
```

### Step 3: Build Cryptographic Bill of Materials
Document all findings with resource ID, algorithm type, key size, expiry date, and dependent services.

### Step 4: Prioritise Migration
1. Keys and certificates exposed to internet traffic first
2. Long-lived keys with high blast radius second
3. Internal service-to-service encryption third

## NIST PQC Standards Reference

| Standard | Algorithm | Use Case |
|----------|-----------|----------|
| FIPS 203 | ML-KEM | Key encapsulation, replacing RSA and ECDH key exchange |
| FIPS 204 | ML-DSA | Digital signatures, replacing RSA-PSS and ECDSA |
| FIPS 205 | SLH-DSA | Digital signatures, hash-based alternative |

## NCSC UK PQC Migration Guidance

The UK National Cyber Security Centre requires organisations to treat PQC migration as a multi-year technology programme. Complete cryptographic discovery, define migration goals, and produce an initial plan by 2028. Complete the highest-priority migrations and refine the roadmap by 2031. Complete migration across systems, services, and products by 2035.

Key requirements:

- Maintain a complete inventory of systems and services that depend on public-key cryptography.
- Prioritise services that protect critical, sensitive, or long-lived data.
- Record supplier, protocol, hardware, and trust-chain dependencies.
- Build cryptographic agility into transition designs and plan for classical and PQC mechanisms to coexist temporarily.
- Use standards-compliant implementations from trusted libraries and products instead of creating custom algorithms.

Guidance: https://www.ncsc.gov.uk/guidance/pqc-migration-timelines

## ENISA Post-Quantum Cryptography Recommendations

ENISA recommends preparing protocols and systems for PQC integration before cryptographically relevant quantum computers arrive. Migration planning must consider application-specific trade-offs, protocol changes, interoperability, and the operational cost of replacing established public-key infrastructure.

Key requirements:

- Assess each cryptographic use case and its confidentiality or authenticity lifetime.
- Make new protocols and major protocol revisions PQC-aware.
- Consider hybrid implementations that add post-quantum protection to established classical mechanisms during transition.
- Evaluate algorithm families, parameter choices, implementation maturity, and performance for each workload.
- Preserve defence in depth and avoid weakening current security while adding quantum resistance.

Recommendations: https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation

## Harvest Now Decrypt Later Risk Assessment

Harvest Now Decrypt Later attacks capture encrypted information today so that an adversary can retain it until a quantum computer can break the classical key establishment. The risk exists before a cryptographically relevant quantum computer is available because collection can already be under way.

Assess HNDL risk using:

- The sensitivity and useful lifetime of encrypted data.
- Internet exposure and the feasibility of passive traffic collection.
- Whether RSA, finite-field Diffie-Hellman, or elliptic-curve key establishment protects the session.
- Key reuse, key age, certificate lifetime, and the blast radius of compromise.
- Dependencies on suppliers, protocols, hardware security modules, and certificate authorities.
- The time required to discover, test, deploy, and validate a replacement.

OpenShield marks internet-facing App Service TLS findings as directly HNDL-exposed. Key assets are also marked exposed when they may protect stored or transmitted data. Certificate-only signature risks are tracked separately because their primary quantum threat is authentication or signature forgery.

## CBOM Schema

OpenShield generates an `OpenShield-CBOM` document with schema version `1.0` from AZ-PQC findings in the latest completed scan.

| Field | Meaning |
|-------|---------|
| `generated_at` | ISO 8601 completion time of the source scan |
| `subscription_id` | Azure subscription assessed by the source scan |
| `summary` | Counts by asset type, high-risk assets, and HNDL exposure |
| `migration_guidance` | Canonical NIST FIPS 203, 204, and 205 plus NCSC and ENISA references |
| `assets` | Risk-ranked classical cryptographic assets |
| `cbom_asset_type` | `tls_configuration`, `asymmetric_key`, or `certificate` |
| `algorithm_type` | Classical cryptographic algorithm or protocol mechanism observed |
| `quantum_risk_score` | Integer from 1 to 10 used to order migration work |
| `internet_exposed` | Whether the asset is directly internet-facing |
| `harvest_now_decrypt_later_exposed` | Whether retained data or traffic may be decrypted in the future |
| `hndl_risk_description` | Explanation of the HNDL or related quantum exposure |
| `migration_priority` | `HIGH`, `MEDIUM`, or `LOW` migration priority |
| `recommended_target_algorithm` | Recommended NIST-standardised PQC replacement |

## Compliance Mapping

| Framework | Control | Requirement |
|-----------|---------|-------------|
| NIST CSF | PR.DS-2 | Data in transit is protected using quantum-safe algorithms |
| ISO 27001 | A.8.24 | Rules for the use of cryptography must address quantum threats |
| CIS Azure | 8.1 | Key management must include post-quantum migration planning |
| SOC 2 | CC6.7 | Encryption protecting data in transit must be quantum-safe |
