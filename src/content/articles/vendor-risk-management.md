---
title: "Why Your Vendor Risk Program Is Broken (And How to Fix It)"
description: "62% of breaches involve a third party. Your vendor questionnaire didn't stop MOVEit. A completed questionnaire is a self-attestation — not evidence, not verification."
pubDate: 2026-04-11
category: "Risk Management"
tags: ["Vendor Risk", "Third Party Risk", "Supply Chain", "Cybersecurity"]
coverImage: "/images/articles/vendor-risk-management-cover.png"
linkedinUrl: ""
published: false
featured: false
---
*By Brian Kuzdas | Enterprise IT Architect | Cloud Security · Zero Trust · IAM*

---

## The Questionnaire That Gives You Nothing

Every year, your vendor risk team sends out questionnaires. Vendors fill them out. Your team reviews them. A risk rating gets assigned. The vendor is approved. The business unit gets access. Everyone moves on.

And every year, breaches involving third parties account for the majority of significant incidents across every industry. The Verizon Data Breach Investigations Report has consistently found that 60–62% of breaches involve a third party, either directly or through compromised credentials and supply chain access. In 2023, the MOVEit vulnerability compromised data at over 2,500 organizations—most of which had approved MOVEit as a vendor through exactly this kind of questionnaire-based process.

The questionnaire isn't the problem. The questionnaire-as-assessment mentality is.

A completed vendor questionnaire is a vendor's self-attestation that they're doing the things you asked about. It is not evidence. It is not verification. It is not a security assessment. It is a document that tells you what the vendor believes about themselves—or what they want you to believe about them—on the day they filled it out.

I've reviewed hundreds of vendor security programs at regulated healthcare, financial services, and manufacturing organizations. The ones that actually reduce third-party risk share exactly three characteristics: they tier their vendors by real business risk, they verify instead of trusting attestation, and they treat vendor relationships as dynamic, ongoing risks rather than point-in-time approvals.

This article is a systematic dismantling of what passes for vendor risk management in most organizations, and a concrete framework for doing it better.

---

## The 5 Questions That Actually Matter

Most vendor security questionnaires are 80–150 questions long and answer none of the things you actually need to know. They ask about patch management policies, disaster recovery documentation, security awareness training frequency, and encryption key rotation schedules—all genuinely important security practices, but entirely self-reported and unverifiable through a questionnaire.

There are five questions where the answers—and your vendor's willingness to answer them honestly—tell you most of what you need to know.

### 1. Do You Have a SOC 2 Type II Report, and Can We See It?

Not a SOC 2 Type I. Not a SOC 3. Not an ISO 27001 certificate. A SOC 2 Type II report: a report produced by an independent auditor that describes the controls the vendor has in place *and* tests whether those controls actually worked over a defined period, typically six to twelve months.

A SOC 2 Type II is the minimum credible evidence of a mature security program for any SaaS vendor handling sensitive data. The fact that a vendor has completed a SOC 2 Type II doesn't mean they're secure—it means they've been through an independent assessment of specific control categories and their controls operated effectively enough to pass. That's a floor, not a ceiling.

What you're also looking for: what Trust Services Criteria are in scope? A SOC 2 that only covers Availability doesn't tell you much about Security or Confidentiality. When was the last report period? A SOC 2 with a period ending 18 months ago and a bridge letter is very different from a current report.

### 2. What Is Your Secure Software Development Lifecycle?

For vendors building software you depend on, the most important security question is not whether they patch servers—it's whether they build security into their code. Ask for:
- Threat modeling practices
- SAST (Static Application Security Testing) and DAST (Dynamic Application Security Testing) in the CI/CD pipeline
- Code review requirements before deployment
- Third-party penetration testing (who conducts it, what scope, how often, what happens with findings)
- Vulnerability disclosure and remediation SLAs

A vendor that can't clearly describe their SDLC security controls is telling you that security is bolted on after the fact—if at all.

### 3. Who Are Your Subprocessors and What Data Can They Access?

This is the question that surfaces the tail risk. Vendors don't just process your data—they share it with their own vendors: cloud infrastructure providers, analytics tools, support ticketing systems, monitoring platforms, and development tools. Each of those subprocessors represents an additional attack surface where your data exists.

Industry data consistently shows that the breach vector is often not the primary vendor you approved but a subprocessor two or three steps down the chain. SolarWinds didn't compromise organizations directly—it compromised the update mechanism that organizations trusted, which was itself trusted by security teams that had done all the "right" assessments.

Ask vendors for:
- A current list of subprocessors with names, locations, and the nature of data access
- Their process for assessing subprocessor security
- Contractual obligations flowing down to subprocessors
- Notification procedures when subprocessors change

### 4. What Is Your Incident Notification SLA?

When something goes wrong at your vendor—a breach, a ransomware incident, an unauthorized disclosure of your data—how quickly will you know? In how many hours will they notify you? Through what channel? With what level of detail?

The answer to this question has regulatory implications for many organizations. HIPAA's Breach Notification Rule requires notification to covered entities within 60 days of discovery. GDPR requires notification within 72 hours. If your vendor's notification SLA is "we will notify you in a commercially reasonable timeframe," you have a contractual and regulatory exposure problem.

Push for: notification within 24–48 hours of confirmed incident, defined escalation paths, a named security contact, and incident response playbook documentation.

### 5. Can We Test Your Controls?

This is the question that separates vendors who are confident in their security from vendors who are relying on your assumption that they're secure. Penetration test access, red team exercise results, vulnerability scan results shared under NDA—these are the forms of real verification.

Most vendors will say no, at least initially. The negotiating position: a right-to-audit clause in the contract (the right to commission an independent security assessment at your expense, typically no more than once per year), or the requirement to share annual penetration test results and remediation evidence. The vendors who refuse entirely deserve additional scrutiny.

---

## When a Vendor Won't Share Their SOC 2

A vendor with genuinely nothing to hide will share their SOC 2 Type II report under a mutual NDA. When a vendor refuses, the question is what alternative evidence they can provide and whether that evidence is sufficient for the risk tier you've assigned to them.

**Bridge Letters:** A bridge letter is a written attestation from a vendor's auditor or management that no material changes to the control environment have occurred since the last SOC 2 audit period. Bridge letters are common during the gap between audit periods. They're useful for Tier 2 vendors but insufficient as a primary evidence source for Tier 1 vendors with access to sensitive regulated data.

**Attestation Letters:** Some vendors will provide a management attestation letter signing off on specific security controls you've asked about. These have limited value—they're self-attestation, which is exactly the problem with questionnaires. They may satisfy a compliance checkbox but they don't give you meaningful assurance.

**ISO 27001 Certification:** ISO 27001 is an internationally recognized information security management standard with independent certification. It's a reasonable alternative to SOC 2 for non-US vendors, though the scope of the certification matters—make sure your data processing activities fall within the certified scope.

**Penetration Test Summaries:** A vendor that won't share their full SOC 2 but will share an executive summary of their annual penetration test (conducted by a credible firm) is giving you something more useful than a questionnaire. Push for this.

**When to Walk Away:** If a Tier 1 vendor—one with access to sensitive data, critical operations, or regulated information—cannot produce any credible independent evidence of their security controls after reasonable negotiation, that is not a risk to accept. The risk transfer mechanisms (indemnification clauses, cyber insurance requirements) don't make your data whole after a breach. They fund litigation. Sometimes the right answer is a different vendor.

---

## SLA vs. Actual Security: The Critical Distinction

A 99.9% uptime SLA means your vendor has committed to availability. It says nothing—absolutely nothing—about security. An attacker who breaches your vendor's environment and exfiltrates your data does not cause a downtime event. The systems remain fully available throughout the breach. The SLA is met. You've been breached.

This conflation of availability and security is endemic in vendor contracts and enterprise risk assessments. Business stakeholders negotiate hard for uptime SLAs and data recovery point objectives and barely glance at the security provisions. IT teams review the SLA as "the security and reliability terms." They're not the same thing.

The CIA triad—Confidentiality, Integrity, Availability—exists precisely to distinguish these concerns. Availability SLAs address only the A. They provide no assurance about C or I.

What security contractual provisions actually matter:
- **Data Processing Agreement (DPA):** Defines what data the vendor can process, for what purpose, under what legal basis, and under what security obligations
- **Security Standards Clause:** Binds the vendor to maintain controls equivalent to a specified standard (SOC 2, ISO 27001, NIST CSF) and provides remedies if controls degrade
- **Incident Notification SLA:** As discussed above—critical for regulatory compliance
- **Data Retention and Deletion:** Obligation to delete your data within a defined period after contract termination, with certification of deletion
- **Subprocessor Restrictions:** Limitations on subprocessor use or requirements for advance notice
- **Right to Audit:** Your right to commission independent security assessments
- **Cyber Insurance Requirements:** Minimum coverage levels, evidence of policy, notification if coverage lapses

If your vendor contracts don't contain these provisions, you have a legal and risk management problem—not just a security one.

---

## How to Tier Your Vendors: The Framework That Actually Works

Vendor risk tiering is the most important structural decision in a third-party risk program. The goal is to concentrate your due diligence resources on the vendors where a failure would actually hurt you—not to apply the same level of scrutiny to your coffee vendor and your cloud-hosted EHR.

### Tier 1: Critical — Full Due Diligence Required

Tier 1 vendors have one or more of the following:
- Access to sensitive or regulated data (PII, PHI, financial records, IP)
- Integration with critical operational systems (ERP, LIMS, EHR, authentication infrastructure)
- Ability to affect system availability for mission-critical operations
- Access to privileged credentials or administrative functions

**Due diligence for Tier 1:** Full SOC 2 Type II review, security questionnaire, reference checks on security incidents, penetration test evidence, DPA execution, annual review including updated SOC 2, security contact identified.

### Tier 2: Operational — Standard Due Diligence

Tier 2 vendors are important to operations but don't have access to sensitive data or critical systems. Think: productivity software, communication tools, project management platforms, non-sensitive SaaS services.

**Due diligence for Tier 2:** SOC 2 review or equivalent certification, security questionnaire, DPA for any data processing, biennial review.

### Tier 3: Commodity — Lightweight Due Diligence

Tier 3 vendors are commodity suppliers with no access to sensitive data, no privileged system access, and no critical operational role. Think: office supplies, non-digital services, commodity hardware purchased commercially.

**Due diligence for Tier 3:** Vendor registration, standard commercial terms, no special security assessment required.

**The tiering trap:** Many organizations tier vendors at onboarding and never revisit the tier. A Tier 3 vendor whose scope expands over time—who starts handling some data, who gets broader system access, who becomes operationally critical—can drift from Tier 3 to Tier 1 without any change in due diligence. Tier assignment must be reviewed annually and triggered by scope changes.

---

## The Vendor That Will Breach You Isn't the One You're Watching

Here's the uncomfortable reality of third-party risk: you have visibility into your Tier 1 vendors. You've reviewed their SOC 2, negotiated their contract terms, named a security contact, and set up a review cycle. They're in your system. You're watching them.

The breach is more likely to come from a vendor you're not watching—or a vendor nobody in your organization knows exists.

Research consistently shows that large enterprises have direct relationships with hundreds or thousands of vendors. They have discovered and managed visibility into perhaps 30–40% of those relationships. The rest are shadow vendor relationships: tools purchased on a departmental P-card, SaaS services connected via personal Google accounts, developer tools that were approved in a Slack channel and never went through procurement.

The MOVEit breach provides an instructive example. Progress Software's MOVEit Transfer tool was widely deployed across enterprises and government agencies. Many organizations that were breached had done due diligence on their primary vendors. What they hadn't done was inventory every data transfer tool in use across the organization. MOVEit was often running in a corner of IT or a business unit, connected to sensitive data, not on anyone's vendor register.

**Shadow vendor mitigation requires:**

1. **Automated vendor discovery:** Network traffic analysis and SaaS discovery tools that identify outbound connections to known SaaS platforms, even uncataloged ones
2. **Procurement integration:** Making the vendor risk process low enough friction that business units actually use it rather than routing around it
3. **Annual vendor inventory attestation:** Requiring business unit owners to sign off on a current inventory of all vendor relationships, not just what procurement knows about
4. **Privileged access governance:** Any vendor with access to sensitive systems should require an access request that triggers vendor risk review—regardless of how they got connected

The long tail of vendor risk is real, and it's largely invisible to traditional questionnaire-based programs. Fixing it requires a combination of discovery tooling, governance process, and organizational culture change.

---

## The Third-Party Risk Program That Actually Works

The gap between most organizations' vendor risk programs and an effective one isn't primarily a technology gap or a budget gap. It's a design gap.

Effective third-party risk programs share the following characteristics:

**Evidence over attestation:** Every Tier 1 vendor has independent evidence of their controls on file. SOC 2, penetration test summaries, ISO certifications, bug bounty program data—these are verification mechanisms, not questionnaire supplements.

**Continuous monitoring:** Tools like BitSight, SecurityScorecard, or UpGuard continuously assess vendors' external attack surface, monitoring for exposed credentials, DNS configuration issues, known vulnerabilities in software they use, and dark web intelligence about data exposures. Static annual reviews miss dynamic risk.

**Contractual teeth:** Your contracts have security provisions, not just SLA terms. Incident notification SLAs are real obligations with consequences. Right-to-audit clauses exist and are exercised.

**Integrated offboarding:** When a vendor relationship ends, access is terminated systematically. Data deletion is confirmed and certified. This sounds basic—it isn't universally done.

**Board-level visibility:** The Ponemon Institute's Third-Party Risk Management Study found that only 35% of organizations report third-party risk metrics to the board. Third-party breaches are material events that affect every stakeholder in the organization. They belong in the board risk conversation.

---

## Bottom Line

Third-party risk management is one of the highest-leverage investments in enterprise security—and one of the most poorly executed. The questionnaire-and-approve model persists because it produces artifacts that satisfy compliance auditors while doing relatively little to reduce actual breach probability.

**Practical Takeaways:**

1. Treat vendor questionnaires as starting points, not assessments—always require independent evidence (SOC 2 Type II, ISO 27001) for Tier 1 vendors
2. Tier your vendors based on actual risk (data access + operational criticality), and revisit tiers annually
3. The five questions that matter most: SOC 2? Secure SDLC? Subprocessors? Incident SLA? Can we test controls?
4. Put security provisions in contracts: DPA, incident notification SLA, right-to-audit, data deletion certification
5. Distinguish between SLA (availability) and actual security (confidentiality, integrity)—they're not the same document
6. Build shadow vendor discovery into your program—the breach risk lives in the vendors nobody is watching
7. Implement continuous monitoring for Tier 1 vendors; annual reviews are too infrequent to catch dynamic risk

The 62% of breaches that involve third parties aren't all the result of vendors with terrible security programs. Many are the result of organizations that had acceptable vendor security programs—and weren't watching closely enough, in the right places, on the right vendors.

---

## References

1. Verizon Data Breach Investigations Report 2023. Verizon Business. https://www.verizon.com/business/resources/reports/dbir/

2. Ponemon Institute: Third-Party Risk Management Study. Ponemon Institute LLC, 2022. https://www.ponemon.org

3. NIST Special Publication 800-161 Rev. 1: Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations. NIST, May 2022. https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final

4. ISO/IEC 27001:2022: Information Security Management Systems. International Organization for Standardization. https://www.iso.org/standard/27001

5. SolarWinds Supply Chain Attack Analysis. CISA, January 2021. https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a

6. Cl0p MOVEit Ransomware Campaign. CISA, June 2023. https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a

7. NIST Cybersecurity Framework 2.0. NIST, 2024. https://www.nist.gov/cyberframework

8. SOC 2 Attestation Standards. American Institute of CPAs (AICPA). https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2

---

*Brian Kuzdas is an Enterprise IT Architect with 25+ years of experience specializing in cloud security, zero trust architecture, and enterprise risk management. Connect on LinkedIn: https://linkedin.com/in/brian-kuzdas-a176b945*

#VendorRisk #ThirdPartyRisk #SupplyChainSecurity #Cybersecurity #InfoSec #EnterpriseIT #SecurityArchitecture #RiskManagement #SOC2 #CloudSecurity #DataProtection #CISO
