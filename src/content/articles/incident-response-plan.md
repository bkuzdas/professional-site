---
title: "You Don't Have an Incident Response Plan — You Have a Document"
description: "When the breach happens, someone will pull that binder. They'll stare at it for thirty seconds and realize they have no idea what to do next. The document will have failed them completely."
pubDate: 2026-04-16
category: "Incident Response"
tags: ["Incident Response", "CISO", "Cybersecurity", "Business Continuity"]
coverImage: "/images/articles/incident-response-plan-cover.png"
linkedinUrl: ""
published: false
featured: false
---
There's a binder somewhere in your organization. It has a title like "Information Security Incident Response Plan" and a version number and an approval date. It was last reviewed 18 months ago. It lists contacts who have since left the company. It describes tools you no longer use.

When the breach happens — and for most organizations, it's when, not if — someone will pull that binder. They'll stare at it for thirty seconds, flip to the wrong page, and realize they have no idea what to do next. The document will have failed them completely.

That's not an incident response plan. That's liability documentation.

A real incident response plan is practiced, internalized, and updated continuously. It's the muscle memory your team builds through repetition, tabletop exercises, and post-incident reviews. It's the split-second decisions made correctly at 2 AM when the alerts are firing and the CISO is on the phone.

This article is about the difference — and how to close the gap before it closes around you.

---

## The Document vs. The Plan: Why the Distinction Matters

According to the IBM Cost of a Data Breach 2023 report, the average time to identify a breach is **207 days**. The average time to contain it once identified is **73 days**. That's 280 days total — nearly a full year from initial compromise to containment.

Organizations with a high-maturity incident response program identified and contained breaches in under 200 days total. The cost difference is staggering: companies without tested IR plans paid an average of $5.71 million per breach compared to $3.98 million for companies with mature IR programs. That's a **$1.73 million penalty for not practicing**.

The root cause isn't usually a technology failure. It's a process failure. Teams don't know their roles. Escalation paths are unclear. Nobody has pre-approved authority to take systems offline. Communication to regulators and executives is improvised under pressure.

NIST SP 800-61r2 (the definitive federal guidance on computer security incident handling) is explicit: "An organization's incident response capability should be documented in a policy and procedures document." But NIST also dedicates entire sections to testing, training, and metrics — because documentation without practice is just paper.

The plan must live in people's heads, not just in SharePoint.

---

## The 5 Things Your IR Plan Is Probably Missing

After working with organizations across healthcare, financial services, and manufacturing, I've seen the same gaps again and again. These five elements are consistently absent from "mature" incident response programs:

### 1. Contact Trees with Backup Contacts

Your IR plan lists the CISO's mobile phone. What happens when the CISO is on vacation in Portugal? Every contact in your escalation tree needs a backup — and that backup needs to know they're the backup. During a real incident, I've seen teams spend 45 minutes trying to reach someone who was simply on a flight.

Primary contact, backup contact, tertiary contact. For every role. Tested quarterly to verify numbers are current.

### 2. Defined Communication Authority

Who talks to the press? Who notifies regulators? Who sends the email to the board? If this isn't defined in advance, you will have three executives doing it simultaneously, contradicting each other, and potentially creating legal liability.

Communication authority must be established before the incident. Your legal counsel needs to be in the room (virtually or physically) for any external communication. The spokesperson must be identified and briefed on what can and cannot be said while an investigation is active.

### 3. Pre-Approved Response Playbooks for Top Threat Scenarios

Generic incident response steps are nearly useless under pressure. What you need are scenario-specific playbooks: ransomware, business email compromise, insider threat data exfiltration, cloud misconfiguration exposure, credential stuffing against your customer portal.

Each playbook should be pre-approved, meaning leadership has already blessed the contained actions your team can take without additional approval. Can the SOC team block outbound traffic to a suspicious IP range without a change advisory board approval? If the answer is "I don't know," the playbook isn't done.

### 4. External Counsel and Forensics Firm Pre-Engagement

During a breach is the worst time to be Googling "incident response firms." Pre-engagement with an external forensics firm and a breach-specialized attorney is not paranoia — it's basic risk management. These relationships take weeks to establish properly. Most good forensics firms have retainer arrangements specifically for this purpose.

Your cyber insurance carrier may have preferred vendors, and using them may be required for coverage. Know this before the incident.

### 5. A Tabletop Exercise Schedule with Accountability

The exercise schedule must be on someone's calendar. Not "we should do one this year" — a specific date, a specific scenario, specific participants, and a specific debrief deliverable. I'll address why most tabletops are useless in the next section.

---

## Tabletop Exercises: Why Most Are Theater

A tabletop exercise where participants sit in a conference room and describe what they "would" do if an incident occurred is not incident response practice. It's storytelling. It tells you nothing about whether your team can actually execute under pressure.

Effective tabletop exercises have four characteristics:

**They inject new information mid-exercise.** Real incidents don't unfold linearly. They start with partial information, get worse, then get complicated. Your tabletop should simulate this. Thirty minutes in, you reveal that the breach started two weeks ago. An hour in, a reporter calls. Two hours in, you discover a third-party vendor is also affected. How does your team adapt?

**They involve executives.** Most IR plans break down at the executive communication layer. Your CISO has a plan. Your GC has concerns. Your CEO wants to know if they need to issue a statement. Your CFO is worried about SEC disclosure obligations. These tensions must be exercised, not assumed away.

**They use realistic scenarios based on your actual threat landscape.** A manufacturing company running legacy OT systems should be tabletoping ICS/SCADA ransomware, not generic phishing. A healthcare organization should be tabletoping a PHI exfiltration event with HHS notification timelines. Scenario selection must match your risk profile.

**They have a real debrief.** The debrief isn't "good job everyone." It's a structured review: What did we discover we didn't know? What decision points took longer than expected? Which parts of the plan were followed versus improvised? What are the three changes we're making before the next exercise?

SANS Institute research on incident response maturity consistently identifies exercised programs as 40-60% faster at containment than untested programs. The exercises aren't the overhead — they're the investment.

---

## Regulatory Notification: Know the Clock Before the Incident

Nothing creates more chaos during an active incident than discovering the notification requirements for the first time. These are not negotiable, and the penalties for non-compliance can exceed the cost of the breach itself.

**HIPAA Breach Notification (Healthcare):** Covered entities have 60 calendar days from the date of discovery to notify affected individuals, HHS, and (for breaches affecting 500+ residents of a state) prominent media outlets. The 60-day clock starts at discovery — not at confirmation. If your security team discovers something suspicious on Day 1 but "doesn't confirm it's a breach" until Day 45, regulators may not accept that characterization. HHS HC3 guidance is explicit: when in doubt, notify.

**SEC Cybersecurity Disclosure Rule (Public Companies):** As of December 2023, publicly traded companies must disclose material cybersecurity incidents within **4 business days** of determining materiality. This isn't 4 days from discovery — it's 4 days from the determination that the incident is material. That determination must be made promptly. Your IR plan must include a defined process for making this determination, with legal and executive involvement.

**State Attorney General Notification:** 50 states now have breach notification laws. Most require notification to the state AG and affected residents within 30-90 days. Some states (e.g., California, New York) have additional specific requirements for certain data types. If you operate across multiple states — and virtually all organizations do — you need a notification matrix that maps data type and state to notification timeline and format.

**GDPR (if applicable):** 72-hour notification to supervisory authority. No exceptions. If you process EU resident data, this timer runs regardless of your US obligations.

The bottom line: these clocks start ticking whether or not your IR team is ready. Build the notification decision tree into your playbooks before you need it.

---

## The First 15 Minutes of a Real Incident

In incident response, the first 15 minutes are disproportionately consequential. The actions — or inactions — in the opening moments of a confirmed incident largely determine whether you recover cleanly or suffer catastrophic, compounding damage.

The core tension in the first 15 minutes is **containment versus investigation**. Law enforcement and digital forensics professionals will often want systems preserved in their compromised state for evidence collection. Your operations team wants the bleeding stopped immediately. Both are right, and both are in conflict.

Your pre-approved playbooks must resolve this tension before the incident. For most enterprise environments, the answer is: **contain first, preserve second**. Isolate affected systems from the network. Do NOT power them off (this destroys volatile memory forensics). Document everything with timestamps. Begin your parallel forensics preservation process.

The specific actions in the first 15 minutes should be committed to a one-page reference card that is physically accessible (not just in a SharePoint that may be down). The card should answer:

1. Who to call first (and their backup)
2. Network isolation procedure for affected segment
3. How to preserve volatile state (memory dump, active connection capture)
4. What to NOT do (don't reboot, don't delete logs, don't talk to press)
5. How to open the incident bridge/war room

Time-stamped logging begins at minute zero. You will need a precise timeline for forensics, insurance claims, legal proceedings, and regulatory response. If your team can't reconstruct exactly what happened when, your incident response has already failed.

The SANS Incident Handler's Handbook identifies the first responder's documentation discipline as one of the most critical — and most commonly skipped — elements of effective incident response. Train your team to document as they act, not after.

---

## NIST 800-61 vs. Reality: The Gap That Costs You

NIST SP 800-61r2 defines a lifecycle for incident response that is well-designed, comprehensive, and largely ignored in practice. Understanding the gap between the framework and real-world execution is essential to closing it.

**NIST's Framework:**

1. **Preparation** — Policies, tools, team training, communication plans, pre-engagement with partners
2. **Detection and Analysis** — Identifying incidents, understanding scope and severity, prioritizing response
3. **Containment, Eradication, and Recovery** — Stopping the spread, removing the threat, restoring operations
4. **Post-Incident Activity** — Lessons learned, process improvement, evidence handling

**What Organizations Actually Do:**

1. **Preparation** — Skipped, or limited to writing the document
2. **Detection and Analysis** — Alert fatigue means detection is delayed; analysis is reactive and inconsistent
3. **Containment** — Driven by operations pressure to restore service, not methodical containment
4. **Recovery** — Rushed; the root cause is not confirmed before systems are restored
5. **Post-Incident Activity** — Skipped due to pressure to return to normal operations

The NIST framework works. The problem is that organizations invest in the technology layers (SIEM, EDR, SOAR) and skip the process and people layers. A $2 million SIEM implementation is useless if the analyst doesn't know the escalation procedure.

NIST explicitly identifies **preparation** as the most important phase — not detection, not containment. Preparation is what determines how effectively every other phase executes. The time to buy the fire extinguisher is not while the building is burning.

Key NIST recommendations that are consistently under-implemented:
- Documented incident classification scheme with specific severity criteria
- Designated incident response team with trained backups for each role
- Pre-positioned tools and access rights (not waiting for approval during the incident)
- Relationships with legal, law enforcement, and external forensics established pre-incident
- Metrics and reporting structure to measure IR program effectiveness over time

If you're measuring your IR program by whether the document exists, you're measuring the wrong thing. Measure mean time to detect (MTTD), mean time to respond (MTTR), percentage of incidents that escalated beyond initial severity estimate, and percentage of post-incident action items closed within 30 days.

---

## Bottom Line: What to Actually Do This Quarter

The gap between "having a document" and "having a plan" is closed through action, not aspiration. Here's what matters:

**1. Audit your contact tree this week.** Call five numbers in your IR plan. How many are current? How many have backups? Fix the gaps.

**2. Schedule a tabletop exercise in the next 60 days.** Not "sometime this year." A specific date, a specific ransomware scenario, mandatory executive participation. Use the CISA Tabletop Exercise Package (CTEP) if you need a starting framework — it's free.

**3. Pre-engage a forensics firm.** Issue an RFP to two or three firms. Establish a retainer. This is a budget item, not an optional one.

**4. Build your notification matrix.** For your industry, your data types, your geographic footprint — what are the notification obligations? Who has authority to make the call? Document this separately from the main IR plan so it's findable under pressure.

**5. Run your metrics.** If you have a SIEM or SOC, pull MTTD and MTTR for the last six months. If those numbers are trending wrong, you have quantifiable evidence for investment.

**6. Read NIST 800-61r2.** It's 79 pages and it's free. It contains more practical guidance than most $50,000 consulting engagements. Specifically, study Appendix A (incident handling checklist) and Section 3.1 (preparation).

The organizations that recover cleanly from incidents are not the ones with the best firewalls. They're the ones whose people knew exactly what to do at 2 AM.

---

## References and Further Reading

1. **NIST SP 800-61r2** — Computer Security Incident Handling Guide. National Institute of Standards and Technology. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf

2. **IBM Cost of a Data Breach Report 2023** — IBM Security / Ponemon Institute. https://www.ibm.com/reports/data-breach

3. **SANS Incident Handler's Handbook** — Patrick Kral, SANS Institute. https://www.sans.org/white-papers/33901/

4. **CISA Incident Response Guide** — Cybersecurity and Infrastructure Security Agency. https://www.cisa.gov/sites/default/files/2024-03/Joint-Guidance-Cybersecurity-Incident-Response-Guide_508c.pdf

5. **HHS HC3: HIPAA Breach Notification Requirements** — HHS Health Sector Cybersecurity Coordination Center. https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html

6. **SEC Cybersecurity Disclosure Rule (Final Rule)** — Securities and Exchange Commission, August 2023. https://www.sec.gov/rules/final/2023/33-11216.pdf

7. **CISA Tabletop Exercise Packages (CTEPs)** — https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages

---

#IncidentResponse #CyberSecurity #NIST #SecurityOperations #CISO #EnterpriseIT #DataBreach #RiskManagement #HIPAA #InformationSecurity
