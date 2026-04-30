---
title: "SOC 2 vs HIPAA: Why Having Both Doesn't Mean You're Secure"
description: "LastPass. Okta. Twilio. All had SOC 2 Type II. All were breached in 2022. Compliance is not a security posture — it's a snapshot of a moment attackers don't respect."
pubDate: 2026-04-12
category: "Compliance"
tags: ["SOC 2", "HIPAA", "Compliance", "Healthcare", "Vendor Risk"]
coverImage: "/images/articles/soc2-vs-hipaa-cover.png"
linkedinUrl: ""
published: false
featured: false
---
**Author:** Brian Kuzdas | Enterprise IT Architect | [LinkedIn](https://linkedin.com/in/brian-kuzdas-a176b945)

---

Here's a scenario I've watched play out more times than I care to admit. A healthcare organization is onboarding a new vendor — maybe a cloud-based analytics platform, maybe a patient engagement tool. The security team does their due diligence. They send over the standard vendor assessment questionnaire. Among the requests: "Please provide evidence of your security compliance posture."

The vendor responds promptly. They attach a SOC 2 Type II report — freshly minted, unqualified opinion from a Big Four auditor. They also include a HIPAA attestation letter from their compliance officer, stating that their platform has been assessed against the HIPAA Security Rule and found to be in compliance. The security team reviews both documents. Checks the box. Sends the approval downstream.

Three months later, the vendor discloses a breach. Patient records exposed. A misconfigured cloud storage bucket had been publicly accessible for sixty days before anyone noticed. PHI was sitting in plain text, indexed by search engines. The OCR investigation begins.

Both documents were real. Both were accurate. And both were completely useless as indicators of the vendor's actual security posture. This is the core problem with how the industry uses SOC 2 and HIPAA compliance — not as floor-level baselines that enable deeper scrutiny, but as finish lines that stop the conversation.

---

## What SOC 2 Actually Tests (And What It Doesn't)

SOC 2 — Service Organization Control 2 — is a framework developed by the American Institute of Certified Public Accountants (AICPA). It's built around what the AICPA calls the Trust Services Criteria (TSC), which were formalized in the 2017 revision and replace the older Trust Services Principles. The five criteria are:

1. **Security (CC series)** — the common criteria, required for all SOC 2 reports. Covers logical and physical access controls, system operations, change management, risk mitigation, and monitoring.
2. **Availability** — whether the system is available for operation and use as committed or agreed.
3. **Processing Integrity** — whether system processing is complete, valid, accurate, timely, and authorized.
4. **Confidentiality** — whether information designated as confidential is protected as committed or agreed.
5. **Privacy** — whether personal information is collected, used, retained, disclosed, and disposed of in conformity with the commitments in the entity's privacy notice.

The vast majority of SOC 2 reports only include the Security criteria. Availability, Processing Integrity, Confidentiality, and Privacy are optional add-ons that a service organization elects to include or exclude. When a vendor hands you a SOC 2 report, there's a reasonable chance it only covers one of the five criteria.

There are two report types. **Type I** assesses the design effectiveness of controls at a single point in time. An auditor reviews whether the controls described by management *exist* and are *designed* to meet the criteria. **Type II** adds operating effectiveness: the auditor tests whether those controls actually functioned over an audit period, typically six to twelve months.

Type II sounds rigorous, and relative to Type I it is. But there is a critical nuance buried in how both work: **the scope of what's tested is defined by management, not by the auditor.** The service organization writes a description of their system in Section 3 of the report — which systems are included, which services, which infrastructure, which third-party relationships. The auditor then audits that description. If a system isn't in the description, it isn't in scope. If a process isn't mentioned, it isn't tested.

This is not a flaw in the design of SOC 2 — it's an inherent feature of an attestation framework. But it means a company can describe a control as "employees review access logs on a monthly basis" and be fully SOC 2 compliant with that control, even if monthly log reviews are wholly inadequate for detecting an active intrusion. The auditor's job is to verify that the described control operates as described — not to evaluate whether the control is *sufficient*.

Auditors performing SOC 2 engagements do not conduct penetration tests. They do not run threat models. They do not evaluate whether the described security posture would survive a sophisticated adversary. They test whether the control environment management described to them was operating as described. These are fundamentally different activities.

The result: a SOC 2 Type II report tells you that during the audit period, the in-scope systems operated in accordance with the controls that management said were in place. It tells you almost nothing about whether those controls are adequate for your use case, whether the out-of-scope systems have been hardened, whether the vendor has a mature threat detection capability, or whether the subprocessors handling your data have any controls at all.

---

## What HIPAA Actually Requires

The Health Insurance Portability and Accountability Act of 1996, and its implementing regulations at 45 CFR Part 164, establishes what's known as the HIPAA Security Rule. Unlike SOC 2, HIPAA is a federal law — it carries civil and criminal liability. It applies to covered entities (health plans, healthcare providers, healthcare clearinghouses) and their business associates (vendors who create, receive, maintain, or transmit PHI on behalf of a covered entity).

The Security Rule organizes its requirements into three categories of safeguards:

**Administrative Safeguards** — the policies, procedures, and documentation a covered entity must implement. This includes the Security Management Process (§164.308(a)(1)), which requires a formal risk analysis and risk management program. Also included: assigned security responsibility, workforce security controls, information access management, security awareness training, security incident procedures, contingency planning, and evaluation.

**Physical Safeguards** — facility access controls, workstation use policies, workstation security, and device and media controls.

**Technical Safeguards** — access controls, audit controls, integrity controls, transmission security (encryption), and person or entity authentication.

Within these safeguards, HIPAA distinguishes between **required** and **addressable** specifications. This distinction is widely misunderstood. Addressable does not mean optional. It means: implement the specification if it is reasonable and appropriate for your environment; if it is not, document *why* it is not, and implement an equivalent alternative if one exists. A covered entity that skips an addressable safeguard without a written rationale is not HIPAA compliant — they've simply created a documented vulnerability with a legal liability attached to it.

Perhaps the most consequential requirement — and the most commonly under-implemented — is the ongoing risk analysis mandated by §164.308(a)(1)(ii)(A). This isn't a one-time checkbox. The regulation requires covered entities to conduct "an accurate and thorough assessment of the potential risks and vulnerabilities to the confidentiality, integrity, and availability of electronic protected health information held by the covered entity." The word "ongoing" is not in the statute by accident. HHS OCR guidance explicitly states that risk analyses must be conducted periodically and updated when significant operational or environmental changes occur.

In practice, most organizations conduct a risk analysis once. They often commission it from a consultant, receive a report, file it away, and revisit it only when preparing for a renewal or responding to an audit notice. This creates precisely the kind of stale risk picture that allows vulnerabilities to accumulate silently.

**HIPAA has no certification process.** There is no HIPAA certification body. There is no annual HIPAA audit that results in a pass/fail credential. What exists is HHS OCR — the Office for Civil Rights — which investigates after breaches. The liability model is inverted from what most organizations assume: you are presumed compliant until a breach reveals otherwise.

OCR Resolution Agreements make the financial stakes concrete. **Community Health Systems** paid $4.5 million after a breach affecting 4.5 million patients, with OCR finding failures in risk analysis and risk management. **Anthem** paid $16 million — the largest HIPAA settlement at time of agreement — after the 2015 breach affecting nearly 79 million individuals, with OCR noting failures in risk analysis, IT system review, and access control. **UCLA Health** paid $865,000 for inadequate access controls and failure to implement technical security measures. These aren't edge cases — they're systemwide failures hiding behind paperwork that made organizations *feel* compliant.

---

## The Gap Between Compliance and Security

Let me be direct about the core thesis: **compliance is a moment in time; security is every moment.** This isn't a critique of SOC 2 or HIPAA as frameworks — both serve important purposes and represent genuine minimum floors. The problem is the organizational behavior that treats clearing the compliance bar as equivalent to being secure.

SOC 2 testing happens within an audit window. The Type II audit period might be January 1 through December 31. The auditor selects samples from that period and tests whether controls operated. What the audit cannot capture: the misconfigured S3 bucket that was public for three weeks in March before someone noticed. The service account whose password was credential-stuffed in September and used for lateral movement. The npm package in the CI/CD pipeline with a known critical CVE that no one patched because the SBOM process wasn't mature enough to flag it. None of these appear as SOC 2 findings because none of them were in scope.

The HIPAA risk analysis problem compounds this. When organizations treat the annual risk analysis as a compliance deliverable rather than an operational input, the resulting document calcifies. The threat landscape from 2021 doesn't accurately represent 2024 attack patterns. LLM-assisted phishing, AI-generated credential stuffing, supply chain compromises of CI/CD tooling — these aren't in most risk analyses because most risk analyses weren't written when these threats became prominent.

The evidence is not theoretical. Three well-documented 2022 breaches illustrate the compliance-security gap with precision:

**LastPass (August 2022):** At the time of the breach, LastPass held a SOC 2 Type II certification. The breach vector was a senior engineer's home computer — specifically a vulnerable media software installation on a personal device. That device was used to access the corporate development environment. Personal devices used by employees for corporate access were not in the SOC 2 system description scope. The audit said nothing because it couldn't say anything — the attack surface wasn't in the report.

**Okta (January 2022 / March 2022):** Okta disclosed a breach related to the Lapsus$ threat actor group. The attacker compromised a third-party support vendor — Sitel Group (later Synnex), which had access to Okta's customer support tools. Okta held a SOC 2 Type II certification. Sitel, the third-party vendor whose engineer's workstation was compromised, was not covered by Okta's SOC 2 report. Subprocessors are frequently excluded from SOC 2 scope. The audit covered Okta; the breach came through a vendor that Okta's audit didn't touch.

**Twilio (August 2022):** Twilio disclosed that attackers used SMS phishing — smishing — to impersonate Twilio's IT department and convince employees to click links that harvested credentials. Twilio held SOC 2 Type II certification. Security awareness training is a control in SOC 2's CC1/CC2 series. Having training in place and having training that defeats a sophisticated, real-time social engineering campaign are two entirely different things. The audit confirmed the former. The breach demonstrated the limits of the latter.

None of these are indictments of the organizations' compliance programs — all three were real, audited, maintained programs. They're illustrations that a compliance document is a snapshot of a controlled environment, not a guarantee of resilience against live adversaries who operate entirely outside the boundaries of what auditors sample.

---

## Why a Vendor Can Be SOC 2 Type II and Still Be Breached

The LastPass, Okta, and Twilio incidents aren't anomalies — they're instructive because they each illustrate a different structural gap in how SOC 2 scope works.

**The Personal Device / Shadow IT Gap (LastPass pattern):** SOC 2 system descriptions cover "the system" — typically defined as production infrastructure, corporate-managed endpoints, and named services. When engineers use personal equipment to access development environments, those devices exist entirely outside the audit scope. Bring-your-own-device policies and remote work have dramatically expanded the attack surface that SOC 2 doesn't touch. A compromise of a personal device that has credentials to corporate systems is, from an audit standpoint, invisible.

**The Subprocessor Gap (Okta pattern):** Your vendor's SOC 2 doesn't cover their vendors. Cloud vendors frequently use other cloud vendors — for monitoring, support tooling, customer success platforms, identity providers. Section 3 of a SOC 2 report will list "complementary user entity controls" and sometimes "complementary subservice organization controls," but unless the vendor has a Type II report that explicitly covers those subprocessors (or uses a carve-in approach), the chain of trust breaks at the first tier. In healthcare contexts, this is directly relevant because a BAA with your vendor doesn't automatically flow down to their subprocessors in the form of equivalent controls.

**The Human Factor Gap (Twilio pattern):** Social engineering and phishing are notoriously difficult to audit. SOC 2 requires security awareness training. It does not — and cannot — guarantee that training produces behavior that defeats a targeted, real-time phishing campaign. The Lapsus$ group, active in 2022 and responsible for multiple high-profile breaches, specifically targeted employees with social engineering because they understood that technical controls were relatively mature while human-factor controls lagged. Auditors review training completion records. They can't audit human judgment under pressure.

**The Scope Election Gap:** Cloud providers offer dozens or hundreds of services. A SOC 2 report may cover a specific subset. AWS, Azure, and GCP all maintain SOC 2 reports — but not every service offered is covered in those reports. If you're storing PHI in a service that's not on the covered services list, the SOC 2 report is irrelevant to that workload. This same principle applies to SaaS vendors: the audit may cover their primary product but exclude their analytics infrastructure, their internal tooling, or services they recently acquired.

**The Time Gap:** A SOC 2 Type II audit with a December 31 report date reflects the period ending December 31. You're reading it in March. The organization has had three months to change, add systems, onboard new vendors, and modify controls. The report you're holding is already partially historical. A vendor who underwent significant architectural changes after the audit period has a SOC 2 report that describes a system that no longer entirely exists.

When evaluating vendor security, a SOC 2 Type II report should be the *beginning* of the conversation, not the end of it. The document tells you that a competent auditor, working with management-provided descriptions, found that described controls operated as described. That's useful. It's just not sufficient.

---

## How to Use Both Frameworks Without Being Fooled

Used correctly, SOC 2 and HIPAA compliance evidence are valuable inputs into a vendor assessment process. The mistake isn't asking for them — it's accepting them as self-contained proof of security adequacy. Here's how to extract genuine signal from each.

**When evaluating SOC 2:**

Start with the report type. Type I is a design opinion at a point in time — useful for startups without operational history, not sufficient for production healthcare workloads. For mature vendors handling PHI, require Type II with an audit period of at least six months, ideally twelve.

Read Section 3 of the report — the system description. This is where scope is defined. Look for explicit exclusions, references to subservice organizations, and "complementary user entity controls" (CUECs) — controls that are your responsibility, not the vendor's. CUECs are frequently overlooked; they represent areas where the vendor's SOC 2 relies on *you* implementing controls on your side.

Ask specifically about what's *not* in scope. Good vendors will have a clear answer. Evasive answers about scope are a yellow flag.

Ask whether subprocessors handling your data have their own SOC 2 reports, and whether those are available for review.

**When evaluating HIPAA:**

Do not accept an attestation letter as evidence of compliance. Anyone can write an attestation letter. Ask for the most recent risk analysis document — the actual assessment, not a summary. Ask when it was conducted, who conducted it (internal vs. third-party), and what methodology was used. A risk analysis done four years ago against a system that has undergone significant changes is not compliant with the ongoing requirement.

Ask to review the Business Associate Agreement before signing. BAAs vary dramatically in quality. A BAA that does not address breach notification timelines, subprocessor obligations, and data return/destruction provisions is a liability, not a protection.

| **Question to Ask** | **What to Look For** |
|---|---|
| What does your SOC 2 cover? | Named services, explicit scope, audit period length |
| What's excluded from SOC 2 scope? | Specific systems, subprocessors, acquired entities |
| Do your subprocessors have SOC 2 reports? | Availability and recency of those reports |
| When was your last risk analysis? | Recency, methodology, who conducted it |
| Who performed the risk analysis? | Third-party assessor vs. internal team |
| What's your incident response plan? | Documented plan with defined notification timelines |
| How do you handle SOC 2 findings? | Evidence of remediation, not just disclosure |
| What CUECs are in your SOC 2? | Understanding of shared responsibility |

**The HITRUST option:** For healthcare organizations seeking a more rigorous third-party validation than SOC 2 or HIPAA compliance alone, HITRUST CSF (Common Security Framework) merits consideration. HITRUST r2 certification — the most rigorous tier — requires a full validated assessment by a HITRUST-approved external assessor against prescriptive control requirements. Unlike SOC 2, the control requirements are not management-defined; HITRUST specifies the controls and the assessor validates against them. HITRUST also incorporates HIPAA requirements as a mapped subset, meaning a HITRUST r2 certification simultaneously addresses HIPAA technical safeguard requirements in a more auditable way. It's more expensive and time-consuming than a SOC 2 audit, which is precisely why it provides more signal.

---

## The Right Mental Model: Compliance Is the Floor, Not the Ceiling

Every major compliance framework — SOC 2, HIPAA, PCI-DSS, ISO 27001, FedRAMP — represents a floor. It's the minimum viable security standard that a committee of experts agreed upon, typically several years before you're reading this. Frameworks lag technology by three to five years. The HIPAA Security Rule was finalized in 2003. The original threat model was dial-up connections and physical media. The core requirements remain relevant, but the implementation guidance was written before cloud computing was a mainstream enterprise pattern.

Treating compliance as a ceiling — as the goal of the security program — means accepting the threat model of 2003, 2017, or whenever your chosen framework was last updated, and deciding that it's good enough for the adversary you'll face today. It isn't.

The security posture that actually protects an organization comes from capabilities that compliance frameworks don't directly measure: continuous vulnerability management that identifies and remediates misconfigurations and known CVEs in near-real-time; threat modeling that maps out attack paths before adversaries walk them; red team exercises that test the human and technical controls against realistic attack scenarios; zero trust architecture that doesn't assume anything inside the network perimeter is trustworthy; and a security culture where developers, operations staff, and executives treat security as an operational discipline, not a compliance function.

I want to add a perspective that's specific to my work in FDA-regulated environments. In GxP-validated systems — manufacturing, lab, clinical — there's a cultural concept called "validated equals frozen." Once a system is validated, changes require formal impact assessment, regression testing, and re-validation documentation. This is appropriate for ensuring reproducibility and data integrity in regulated scientific processes.

But the same mindset, when it leaks into security, becomes dangerous. I've seen organizations where the implicit logic runs: "This system is validated. Patching requires re-validation. Re-validation takes six months. Therefore we don't patch." The validation process ensured the system was secure at a point in time. The absence of patching ensures it becomes progressively less secure over the subsequent months and years. Compliance — in this case, 21 CFR Part 11 validation compliance — becomes the justification for security stagnation.

The audit mindset — "we need to document that we did the thing, not necessarily that the thing works" — is one of the most corrosive forces in enterprise security. It produces environments where everyone can prove they followed the process and no one is accountable for the outcome. The outcome is what matters. The outcome is whether patient data stays protected, whether systems stay resilient, whether the organization can detect and respond to threats before they become breaches.

Compliance frameworks tell you what to document. Security culture tells you what to *do*.

---

## Bottom Line

Five things you should do differently after reading this:

1. **Stop treating SOC 2 reports as pass/fail verdicts.** Read Section 3. Understand scope. Ask about exclusions. Treat the report as the beginning of a conversation about the vendor's security posture, not the conclusion of it.

2. **Ask every healthcare vendor for their last risk analysis, not their HIPAA attestation.** A risk analysis is a living document that reveals operational maturity. An attestation letter is a signature. One tells you something; the other performs compliance.

3. **Map the subprocessor chain.** Your vendor's SOC 2 almost certainly doesn't cover all their vendors. Ask explicitly who touches your data and what controls cover those relationships.

4. **For high-risk healthcare workloads, consider requiring HITRUST r2.** It's more prescriptive, more rigorous, and more expensive — which is exactly why it provides more signal than a management-scoped SOC 2 audit.

5. **Build a security culture that treats compliance as the minimum standard, not the goal.** This means continuous vulnerability management, threat modeling, red team testing, and an incident response capability that gets exercised before it needs to be used for real.

The vendor in my opening scenario probably had a well-meaning compliance team. They documented their controls. They hired an auditor. They got the report. They genuinely believed they had done what was required. And they had — the compliance was real.

The patient whose record was exposed in that S3 bucket didn't care about the SOC 2 report. Neither should you.

---

## Citations and References

1. AICPA Trust Services Criteria (2017 revision). Available at: [aicpa.org](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustdataintegrity.html)
2. 45 CFR §164 — HIPAA Security Rule. Available at: [ecfr.gov](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164)
3. HHS OCR Resolution Agreements and Civil Money Penalties. [hhs.gov/hipaa/for-professionals/compliance-enforcement](https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html)
4. Community Health Systems — HHS OCR Resolution Agreement, June 2023. $4.5M settlement.
5. Anthem Inc. — HHS OCR Resolution Agreement, October 2018. $16M settlement.
6. UCLA Health System — HHS OCR Resolution Agreement, July 2016. $865K settlement.
7. LastPass Security Incident 2022. [blog.lastpass.com](https://blog.lastpass.com/posts/notice-of-recent-security-incident)
8. Okta Security Incident Investigation, March 2022. [okta.com/blog/2022/03/oktas-investigation-of-the-january-2022-compromise](https://www.okta.com/blog/2022/03/oktas-investigation-of-the-january-2022-compromise)
9. Twilio Social Engineering Attack, August 2022. [twilio.com/blog/august-2022-social-engineering-attack](https://www.twilio.com/blog/august-2022-social-engineering-attack)
10. Ponemon Institute. "Closing Security Gaps to Protect Patient Data: A Study of U.S. and European Healthcare Organizations."
11. HITRUST CSF Overview. [hitrustalliance.net](https://hitrustalliance.net/product-tool/hitrust-csf/)

---

*This article does not constitute legal or compliance advice. Consult qualified legal counsel and compliance professionals for HIPAA compliance guidance specific to your organization.*

---

#HIPAA #SOC2 #Compliance #HealthcareSecurity #CyberSecurity #InfoSec #AuditTheater #RiskManagement #DataPrivacy #HealthIT
