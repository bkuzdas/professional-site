---
title: "Identity Is the New Perimeter: IAM in Healthcare and Life Sciences"
description: "Healthcare has led every industry in data breach costs for 13 consecutive years. Over 89% of those breaches involve compromised credentials. Identity governance is the security foundation we've been missing."
pubDate: 2026-04-29
category: "Identity & Access"
tags: ["IAM", "Healthcare", "Identity", "Zero Trust", "HIPAA", "MFA"]
coverImage: "/images/articles/iam-healthcare-cover.png"
linkedinUrl: "https://www.linkedin.com/pulse/identity-new-perimeter-iam-healthcare-life-sciences-brian-kuzdas-0gg0c"
published: true
featured: true
---
*By Brian Kuzdas | Enterprise IT Architect | IAM · Healthcare IT · Zero Trust · HIPAA Security*

---

## The Perimeter You Thought You Had Is Gone

Ten years ago, the security conversation in healthcare centered on the perimeter: the firewall that separated your hospital network from the internet, the VPN that extended that perimeter to remote workers, and the assumption that anyone who made it inside the network could be trusted.

That model was never entirely correct. Today, it's a fiction.

Your clinical staff access the EHR from personal iPads at home. Your lab system is integrated with a reference laboratory's API across the open internet. Your medical devices sit on a network segment shared with administrative workstations. Your payers and clearinghouses have direct API connectivity to your billing systems. Your contracted physicians have remote access to clinical systems, as do the vendor engineers servicing those systems. Your nurses access patient data on workstations in corridors, then log off and walk to the next patient.

The perimeter dissolved years ago—not from a single catastrophic breach, but from years of necessary, reasonable business decisions that slowly connected everything to everything else. The healthcare environment, by its nature, requires connectivity that makes traditional perimeter defense obsolete.

What replaced the perimeter as the fundamental security primitive? Identity.

Every access decision—whether a nurse is reading a patient chart, a vendor is accessing a clinical system for maintenance, a developer is deploying a code change, or an automated process is querying a database—is ultimately an identity decision. Is this identity who it claims to be? Is this identity authorized to perform this action? Is this identity behaving the way it normally behaves?

This article is about getting those identity decisions right in one of the most demanding environments in enterprise IT: healthcare and life sciences.

---

## Why Traditional Perimeter Security Fails in Healthcare

Healthcare organizations present unique challenges that make perimeter-centric security models particularly ill-suited:

### The Attack Surface Has Expanded Beyond Control

Modern healthcare IT environments include:
- **Electronic Health Record (EHR) systems** with integrations to dozens or hundreds of downstream systems (lab, pharmacy, imaging, billing)
- **Medical devices** — IV pumps, patient monitors, imaging equipment — many running legacy operating systems that cannot support modern security agents
- **External clinical partners** — reference labs, specialty clinics, consulting physicians — who need read access to clinical data
- **Payers and clearinghouses** with direct billing system connections
- **Remote clinical staff** — hospitalists, telehealth providers, on-call physicians — accessing systems from diverse, uncontrolled endpoints
- **Vendor maintenance access** — the biomedical engineering firm maintaining your infusion pumps, the EHR vendor's implementation team, the radiology software vendor's support engineers
- **Research collaborations** — academic medical centers with data sharing agreements, IRB-approved research protocols pulling de-identified data

Every one of these is an identity that requires access to sensitive clinical systems. Every one of them is a potential breach vector if that identity is compromised, misconfigured, or misused.

### The Numbers Are Stark

The U.S. Department of Health and Human Services Office for Civil Rights (HHS OCR) Breach Portal — the public record of healthcare data breaches — has reported over 700 healthcare data breaches per year for the past several years. The IBM Cost of a Data Breach Report 2023 found that the average cost of a healthcare data breach reached **$10.93 million** — the highest of any industry, and more than twice the global average of $4.45 million. Healthcare has held the most expensive breach title for 13 consecutive years.

Research consistently shows that **compromised credentials are the primary breach vector in healthcare**. HHS OCR data indicates that over 89% of healthcare data breaches involve compromised credentials or unauthorized access resulting from identity and access management failures: shared accounts, excessive privilege, lack of MFA on remote access, and failure to disable access for departed employees.

The breach vector isn't primarily sophisticated malware or zero-day exploits. It's an identity that shouldn't have had access, or an identity that was taken over because its credentials were weak or its access was unprotected by MFA.

---

## The 5 IAM Failures That Cause Breaches

Healthcare organizations' IAM programs fail in predictable ways. These five failure modes appear in virtually every healthcare breach investigation.

### 1. Shared Credentials: The Ubiquitous Anti-Pattern

Walk into a clinical environment and count how many workstations have a printed username and password taped to the monitor or keyboard. The number will surprise you.

Shared credentials exist in clinical environments for understandable reasons: they reduce friction in high-pressure, time-sensitive workflows. Nurses don't want to log in every time they move to a new workstation. Physicians want immediate access to the system in front of them. Shared credentials solve that workflow problem—while simultaneously destroying every security control that depends on individual accountability: audit trails, access logging, behavioral analytics, and individual-level privilege enforcement.

When a shared account is used to access protected health information, you cannot answer the question "who accessed this patient's record?" You have a HIPAA minimum necessary problem, a 21 CFR Part 11 problem, and a forensics problem simultaneously.

The HIPAA Security Rule's requirement for **unique user identification** (45 CFR §164.312(a)(2)(i)) is absolute—it is a Required implementation specification with no conditional language. Shared credentials are a HIPAA violation by definition. They persist because organizations have not invested in solving the workflow problem that shared credentials address.

### 2. Excessive Privilege: The Principle of Least Privilege in Name Only

Most healthcare organizations have role-based access control (RBAC) in their EHR systems—in theory. In practice, the roles have expanded through years of individual exception requests until a "floor nurse" role in many organizations provides access to records across multiple facilities, multiple units, and clinical functions far beyond what any individual nurse's workflow requires.

Excessive privilege amplifies the impact of every credential compromise. A compromised account with minimal privilege can access only what that account needs. A compromised account with excessive privilege—the more common scenario—can access patient records across entire systems, pull reports, modify clinical documentation, or traverse connected systems.

Least privilege is not a one-time configuration. It requires periodic access certification reviews where role assignments are reviewed against actual workflow needs, and where entitlements that haven't been used within a defined period are revoked.

### 3. No MFA on Remote Access

The HHS OCR Breach Portal contains case after case of healthcare organization breaches that began with compromised VPN credentials — valid username and password combinations obtained through phishing, credential stuffing, or purchase on the dark web — used to authenticate to a remote access system with no multi-factor authentication in place.

The healthcare industry knows this. HHS has published guidance on MFA. CISA has issued repeated advisories specifically calling out healthcare organizations' failure to implement MFA on remote access. Yet as of 2023, a significant proportion of small and mid-size healthcare organizations still do not have MFA enforced on all remote access pathways.

For any organization subject to HIPAA, the Security Rule's Risk Analysis requirement (45 CFR §164.308(a)(1)) and Transmission Security requirement (45 CFR §164.312(e)) create a strong argument that MFA on remote access is effectively a required safeguard given the known threat landscape.

### 4. Orphaned Accounts: The Access That Outlives Its Owner

A nurse leaves the organization. HR processes the departure. The EHR account is disabled within 24 hours—but the VPN account, the pharmacy system account, the scheduling tool, the remote desktop access, the payer portal credentials, and the six other system accounts created over five years of employment remain active.

Account proliferation in healthcare is severe. A physician at a large academic medical center may have active credentials in 15–25 different systems, many of which were provisioned ad hoc over years of changing roles and responsibilities. When that physician leaves, the departing employee checklist covers a fraction of the actual active accounts.

The HIPAA Security Rule's termination procedure specification (45 CFR §164.308(a)(3)(ii)(C)) requires a formal termination process that includes access revocation. Meeting the letter of this requirement while missing dozens of active accounts is not uncommon.

Identity governance platforms — SailPoint, Saviynt, One Identity, or equivalent — address this through automated joiner-mover-leaver (JML) workflows that trigger access revocation across integrated systems on a defined schedule linked to HR system events. Without automated provisioning and deprovisioning, the orphaned account problem cannot be solved at scale.

### 5. Poor Offboarding: The Systematic Gap

Related to orphaned accounts but broader: poor offboarding encompasses the entire lifecycle of an identity at termination—not just credential disablement, but credential rotation for shared service accounts the individual may have known, revocation of hardware tokens or physical access credentials, removal from distribution lists and collaboration platforms, and documentation that access revocation was completed and verified.

For privileged users—IT administrators, security personnel, executives with broad system access—offboarding requires additional steps: rotation of any credentials the individual had access to, review of recent privileged activity for any anomalous actions, and removal from all privileged access systems and break-glass accounts.

---

## Privileged Access Management in Clinical Environments

Privileged Access Management (PAM) in healthcare presents unique challenges that don't exist in most enterprise environments.

The most significant is the concept of **break-glass access**: emergency access to patient records in clinical scenarios where normal authentication workflows cannot be followed. A physician responding to a code may need immediate access to a patient's medication history. A nurse in an emergency may need to access a patient record for which they haven't been formally granted access. Clinical informatics systems typically implement break-glass mechanisms that allow override access with after-the-fact audit.

The security challenge with break-glass is dual: the access must be genuinely available in emergencies (making it difficult to add authentication friction), and the access must be comprehensively audited after the fact (making the audit trail critical). Break-glass access that is audited is a security control. Break-glass access that is never reviewed is a backdoor.

**Best practices for break-glass access management:**

1. **Require a break-glass reason code at time of access**, recorded in the audit trail
2. **Alert in near-real-time** to the covered patient's care team and to a security/compliance monitoring system
3. **Review every break-glass access event** within 24–48 hours for appropriateness
4. **Track break-glass frequency by user**: a user who break-glass accesses records 40 times per month has a workflow problem or a misconduct problem; neither should be invisible
5. **Periodic attestation**: require the accessing clinician to document post-access that the access was necessary and appropriate

The PAM platform conversation in healthcare extends to administrative privileged access as well. IT administrators with root or domain admin access to EHR infrastructure represent the highest-privilege identities in the organization—more dangerous, from a breach impact standpoint, than almost any clinical credential. These accounts should be managed through a dedicated PAM solution (CyberArk, BeyondTrust, Delinea/Thycotic) with session recording, just-in-time (JIT) provisioning, and credential vaulting.

---

## HIPAA Minimum Necessary and RBAC Design

The HIPAA Privacy Rule's **minimum necessary standard** (45 CFR §164.514(d)) establishes that covered entities must make reasonable efforts to limit the use and disclosure of protected health information to the minimum necessary to accomplish the intended purpose.

In IAM terms, this is an explicit regulatory mandate for least-privilege access control. Your RBAC design must be grounded in actual clinical workflow analysis—not in the most convenient role structure, not in what the EHR vendor ships as default roles, and not in role structures inherited from the last implementation project.

**Minimum necessary-driven RBAC design principles:**

**Facility-level scoping**: Access should be scoped to the facility or facilities where the clinician actually practices. A nurse working at a single community hospital should not have access to records across a 12-facility health system.

**Unit-level scoping**: Within a facility, access should be scoped to the units or departments relevant to the clinician's role. A floor nurse in internal medicine does not have a workflow need for records in behavioral health or women's health units—access to those areas should require an explicit request or trigger a break-glass with audit.

**Function-level scoping**: Clinical roles should be defined to match actual clinical functions. A medical assistant's role should not include the ability to modify clinical documentation beyond the scope of their practice. An admissions coordinator's role should not include access to clinical notes.

**Temporal scoping**: Contract staff, travelers, and temporary employees should have access that expires automatically at the end of their engagement—not access that requires a proactive deprovisioning action.

---

## Federated Identity Challenges with EHRs

Epic and Oracle Health (Cerner) dominate the EHR market and present significant federated identity challenges that every healthcare IAM architect encounters.

**Epic's identity model** has historically been deeply proprietary. Epic maintains its own user directory (EMP master file), its own authentication stack (Epic authentication, optionally supplemented by external IdP), and its own role and access model. SAML/OIDC integration with external identity providers is supported but requires careful configuration, and the degree of federation possible varies by Epic version and module.

**Common EHR identity integration challenges:**

- **EHR-embedded identities**: Both Epic and Cerner maintain user directories that partially or fully duplicate enterprise directory (Active Directory, LDAP, or cloud IdP) identity data. Keeping these in sync — especially for joiners, movers, and leavers — requires automated provisioning pipelines. Manual synchronization fails at scale.

- **Legacy system authentication**: Many clinical systems that integrate with the EHR still use basic authentication (username/password passed directly, no MFA capability). These systems represent islands of weak authentication that modern IdP integration cannot reach.

- **Single Sign-On complexity**: Clinical staff expect to authenticate once and access all systems. Achieving true SSO across EHR, clinical portals, administrative systems, and ancillary clinical applications is architecturally complex and often involves a mix of SAML, OIDC, Kerberos, and proprietary mechanisms. Okta, Azure AD, and Ping Identity are the most common enterprise IdPs in healthcare, but integration depth varies significantly by system.

- **External identity federation**: Referring physicians, partner organizations, and payers increasingly require access to clinical systems. Managing external identities — ensuring they are correctly scoped, actively maintained, and promptly revoked — requires a structured external identity federation program. B2B identity federation with SAML or OIDC is mature but requires contractual agreements and governance processes.

---

## MFA in Clinical Workflows: Why Fatigue Is Real

Multi-factor authentication is the single most impactful identity control available to healthcare organizations. HHS has clearly communicated its expectation that MFA be implemented for remote access to systems containing PHI. CISA has published explicit guidance for healthcare on MFA implementation.

And yet, MFA rollout in clinical environments consistently encounters a legitimate, serious obstacle: **MFA fatigue in high-throughput clinical workflows.**

A nurse who logs in, logs out, and moves to a different workstation 40 times in a 12-hour shift will encounter 40 MFA prompts if push-based or TOTP authentication is required at every session. The result is one of two bad outcomes: the nurse accumulates so much friction that productivity is meaningfully impaired, or the nurse reflexively approves MFA prompts without reading them—the behavior that enables MFA fatigue attacks.

**Solving MFA in clinical environments requires workflow-aware authentication design:**

**Proximity-based authentication (tap-and-go)**: Proximity card readers attached to workstations, linked to the enterprise IdP, allow clinical staff to authenticate by tapping their hospital badge. Imprivata's Tap-n-Go, Imprivata Confirm ID, and similar solutions allow sub-second workstation authentication with cryptographic assurance. This solves the high-frequency authentication problem while maintaining strong identity verification.

**Risk-based authentication**: Rather than requiring MFA at every authentication event, risk-based (or adaptive) MFA evaluates contextual signals—is this a known device? Is the location expected? Is the access pattern normal?—and elevates authentication requirements when risk signals are present. Accessing the EHR from a hospital workstation during a normal shift triggers low friction. Accessing from an unrecognized device at 3 AM from a new location triggers step-up authentication.

**Shared workstation session management**: Imprivata OneSign and similar solutions support walk-up authentication, allowing multiple clinicians to quickly authenticate on shared workstations without full sign-in cycles. Combined with automatic screen lock based on physical presence detection, this reduces both authentication friction and screen exposure risk.

**SSO with session continuity**: Where HIPAA-compliant workflows allow session continuity, SSO reduces the frequency of authentication events. Clinicians who remain authenticated to a session as they move between workstations (within defined time and location parameters) experience dramatically lower authentication friction without sacrificing auditability.

---

## Bottom Line

Identity is the new perimeter in healthcare, not as a marketing slogan, but as a factual description of where security controls must be applied. The perimeter-centric model was never adequate for healthcare's inherent connectivity requirements. The identity-centric model, implemented correctly, provides stronger, more flexible, and more auditable security.

The path is clear:

**Practical Takeaways:**

1. Eliminate shared credentials — full stop. The workflow problem they solve must be addressed through technology (proximity auth, SSO, tap-and-go) not by abandoning individual accountability
2. Enforce MFA on all remote access pathways — this is the single highest-ROI security control available to healthcare organizations today
3. Implement identity governance for automated joiner-mover-leaver workflows — orphaned accounts are not a people problem, they're an automation problem
4. Redesign your RBAC architecture around HIPAA minimum necessary, not around convenience or inherited role structures
5. Audit break-glass access within 24–48 hours of every event — break-glass without review is a backdoor with extra steps
6. Implement PAM for privileged administrative accounts — session recording, JIT provisioning, credential vaulting
7. Build a structured external identity federation program for referring physicians, partner organizations, and vendors

The $10.93 million average cost of a healthcare data breach, and the 89%+ of breaches that involve compromised or misused credentials, make the ROI calculation straightforward: identity governance is not a nice-to-have in healthcare IT. It's the foundation on which every other security control depends.

---

## References

1. HHS OCR Breach Portal. U.S. Department of Health and Human Services Office for Civil Rights. https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf

2. IBM Cost of a Data Breach Report 2023. IBM Security / Ponemon Institute. https://www.ibm.com/reports/data-breach

3. HIPAA Security Rule: 45 CFR §164 — Security and Privacy. U.S. Department of Health and Human Services. https://www.hhs.gov/hipaa/for-professionals/security/index.html

4. NIST Special Publication 800-63B: Digital Identity Guidelines — Authentication and Lifecycle Management. NIST, June 2017 (updated 2022). https://pages.nist.gov/800-63-3/sp800-63b.html

5. CISA Healthcare Cybersecurity Advisory: Known Ransomware Attack Vectors and Mitigations. CISA, 2022. https://www.cisa.gov/resources-tools/resources/cybersecurity-guidance-healthcare

6. American Hospital Association: Cybersecurity and Risk Advisory. https://www.aha.org/cybersecurity

7. Epic Interconnect and Interoperability Documentation. Epic Systems Corporation. https://www.epic.com/software/interoperability

8. Imprivata Digital Identity Solutions for Healthcare. https://www.imprivata.com

9. NIST Special Publication 800-207: Zero Trust Architecture. NIST, August 2020. https://csrc.nist.gov/publications/detail/sp/800-207/final

10. HHS OCR: Guidance on Risk Analysis Requirements under HIPAA Security Rule. https://www.hhs.gov/hipaa/for-professionals/security/guidance/guidance-risk-analysis/index.html

---

*Brian Kuzdas is an Enterprise IT Architect with 25+ years of experience specializing in IAM, healthcare IT security, HIPAA compliance, and enterprise cloud architecture. He holds certifications in AWS, Azure, Okta, and Databricks. Connect on LinkedIn: https://linkedin.com/in/brian-kuzdas-a176b945*

#Healthcare #HealthcareIT #IAM #IdentityManagement #HIPAA #ZeroTrust #Cybersecurity #EHR #Epic #HealthcareSecurity #InfoSec #PatientDataSecurity #MFA #EnterpriseArchitecture
