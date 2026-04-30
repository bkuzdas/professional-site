---
title: "Why Architecture Reviews Fail (And What Actually Works)"
description: "70% of IT projects fail to meet objectives. Most had architecture reviews. The review process is broken — not because architects aren't skilled, but because the structural incentives reward speed over rigor."
pubDate: 2026-04-21
category: "Enterprise Architecture"
tags: ["Architecture", "IT Governance", "Enterprise IT", "Tech Leadership"]
coverImage: "/images/articles/architecture-reviews-cover.png"
linkedinUrl: ""
published: false
featured: false
---
**By Brian Kuzdas | Enterprise IT Architect | Madison, WI**

---

Picture this scene: a conference room, twelve people, a 47-slide PowerPoint deck. The presenting architect walks through the solution — databases, APIs, cloud components, integration points. A few polite questions. Some head nodding. A box gets checked. The project moves forward exactly as planned.

That's not an architecture review. That's a ceremony.

After 25+ years in enterprise IT — spanning FDA/CGMP validated systems, healthcare interoperability, zero trust implementations, and cloud transformations — I've sat in hundreds of architecture reviews. I've run them, failed at them, and eventually figured out how to make them mean something. The dirty secret of the industry is that most architecture reviews are theater. They exist to satisfy governance requirements, not to actually change outcomes.

This article is about how to fix that.

---

## The Rubber Stamp Problem: Why Most Reviews Don't Work

Let's start with an honest diagnosis. Architecture reviews fail for predictable, structural reasons — and almost none of them are about the quality of the architecture itself.

**Reviews happen at the wrong time.** The most common failure mode: the architecture review is scheduled after the vendor contract is signed, after three months of development has already happened, after the team has built emotional and financial investment in a particular approach. At that point, the review can't change anything meaningful. Any finding that requires a fundamental rethink will be met with "we're too far in" — and that's not wrong. The review is too late to help.

**Reviewers lack real authority.** Advisory boards that can only recommend but not require are advisory boards that will be ignored when inconvenient. If the project sponsor outranks the review board, and timelines are tight, findings get classified as "noted" and never revisited. A review without teeth is a suggestion.

**No pre-defined pass/fail criteria.** What does it mean to pass an architecture review? If nobody agreed on that before the review, the outcome is whatever the room decides to decide — which usually means approval with some politely-worded "action items" that evaporate within two weeks. Without explicit criteria, reviews become subjective and inconsistent.

**Findings disappear.** The review produces a document. The document gets filed in SharePoint. Nobody assigns owners. Nobody sets deadlines. Six months later, nobody remembers what was found and nobody checks whether it was fixed. The institutional memory of the review is the empty checkbox on the governance form.

**The numbers confirm it.** Gartner research indicates that up to 70% of IT projects fail to meet their objectives, with architectural issues frequently cited as a root cause. Yet most enterprises have formal architecture review processes in place. The process exists — it just doesn't work.

The failure isn't architectural incompetence. It's process design. Reviews are structured in a way that guarantees they won't change outcomes.

---

## The 5 Questions Every Architecture Review Must Answer

Here's the corrective framework I've arrived at after years of iteration: every architecture review, regardless of size or complexity, must honestly answer five questions. Not check five boxes — honestly answer five questions. There's a difference.

### 1. Does this align with the enterprise architecture strategy?

Not "does it work?" — "does it fit our target state?"

This is the question that gets skipped most often, because answering it honestly requires that an enterprise architecture strategy actually exists and is well-documented. If it doesn't exist, that's the real finding.

Alignment means more than technology category. A cloud-native target state doesn't just mean "runs in AWS" — it means APIs, not proprietary integrations. It means containerized workloads, not lift-and-shift VMs. It means shared identity provider, not siloed credentials. Projects that are technically functional but architecturally divergent create compounding technical debt that becomes exponentially expensive to unwind.

### 2. What are the security risks, and how are they mitigated?

Not "we use HTTPS." A real threat model.

This means: Who are the threat actors, and what are their capabilities? What data does this system handle, and what's its classification? Where is the trust boundary? What happens if the application layer is compromised — what's the blast radius? How does this integrate with the enterprise identity infrastructure? What secrets does this system hold, how are they managed, and what happens if they're exposed?

In regulated environments — healthcare, life sciences, financial services — this question isn't optional. In FDA/CGMP contexts, a system that can't answer this question isn't just architecturally risky; it's a compliance liability.

### 3. What are the operational implications?

Who gets paged at 2am? What does the runbook look like? What monitoring exists?

This is the question that engineering teams hate and operations teams ask. An architecture that works at launch but is operationally opaque is a maintenance nightmare that will drain on-call engineers for years. The architecture review is the right moment to ask: how will we know when this fails? How long will it take to diagnose? What does recovery look like?

Monitoring, alerting, logging, runbooks, DR procedures — these aren't post-launch concerns. They're architectural decisions. Systems that don't log meaningfully can't be debugged in production. Systems with no DR plan aren't production-ready.

### 4. What is the total cost of ownership?

Not just licensing: integration costs, training, maintenance, eventual migration.

License cost is the visible part of the iceberg. Below the waterline: integration development costs, ongoing integration maintenance, training for staff, support contract terms, the cost of eventual migration when the vendor changes terms or gets acquired, and the cost of dependency lock-in if the vendor's APIs are proprietary.

I've watched enterprises select the cheapest option in the vendor evaluation, then spend three times the saved amount on integration work in year one. TCO analysis isn't accounting pedantry — it's how you avoid predictable financial surprises.

### 5. What is the exit strategy if this fails?

Can we rip it out? What are we locked into?

This question makes vendors uncomfortable and project sponsors nervous, which is exactly why it's essential. Every technology decision is a reversible or irreversible commitment. Irreversible commitments — proprietary data formats, non-standard APIs, deep platform coupling — require higher bars of confidence than reversible ones.

The exit strategy question doesn't assume failure. It forces clarity about optionality. If you can answer "we could migrate away from this in six months with a defined data export" — great. If the answer is "we're completely locked in with no migration path" — that's not disqualifying, but it changes the risk calculus significantly.

---

## Making Reviews Change Outcomes: Structural Fixes

Diagnosing the problem is easy. Fixing it requires structural changes that most organizations resist because they require giving up convenience and timeline certainty.

**Schedule reviews at design time, not delivery time.** The architecture review should happen before any code is written, before any vendor is selected, before any team has invested months of work in a particular approach. This is when the review can actually change outcomes. "Design time" means after requirements are understood but before technical decisions are made. If that seems early, it's because most organizations treat architecture as a deliverable rather than a process.

**Define non-negotiable requirements in advance.** Security standards, compliance requirements, operational standards — these should be documented and published before any review, not negotiated during it. When a project comes to the review board, there should be a published list of requirements that all projects must meet regardless of timeline or budget pressure. "We don't have time to implement proper secrets management" is not a valid response to a non-negotiable security requirement.

**Give the review board real authority.** This is the politically difficult one. The review board needs veto power, not just advisory power. This means organizational backing from senior leadership. It means a clear escalation path when projects push back. It means the review board's findings have teeth. Without authority, reviews are polite conversations. With authority, they're governance.

**Track every finding to closure.** Every finding from every review gets logged with an owner, a deadline, and a severity level. No exceptions. The log is reviewed at the next relevant milestone — go-live, next architecture review, quarterly governance check. Findings don't disappear. They get closed, deferred with documented rationale, or escalated. This single change — genuine finding tracking — transforms review effectiveness more than any other structural improvement.

**Create a tiered review system.** Not every decision needs a full committee review. A tiered approach: major decisions (new platforms, new architectural patterns, new vendor relationships, cross-domain integrations) get the full review with all five questions. Minor decisions (adding a library, choosing between two equivalent services within an approved platform) get a lightweight checklist that can be completed asynchronously. This prevents review fatigue and lets the board focus effort where it matters.

---

## Architecture Review as Risk Management, Not Quality Police

The frame matters enormously. There are two ways to run an architecture review board:

**Wrong frame:** "The review board will catch our mistakes." This positions the review as a quality checkpoint, the board as evaluators, and the project team as subjects of inspection. It's defensive and adversarial. Teams respond by polishing decks to hide rough edges. Hard questions get buried. By the time the review happens, the presentation is designed to get past the board, not to surface genuine risks.

**Right frame:** "The review is how we surface risks before they become incidents." This positions the review as a shared risk management activity. The board and the project team are on the same side — both trying to make the project succeed. Teams that genuinely believe the review board will help them rather than obstruct them bring real problems to the review. They ask hard questions themselves. They document uncertainties rather than projecting false confidence.

The cultural shift required: the review board should be the group that project teams want to talk to *early*, because they're helpful — not the group teams dread talking to late because they're obstacles.

**Document dissenting views.** This is an underused practice with enormous value. If a member of the review board has a concern that gets overruled — the project timeline wins, the business case overrides the technical risk — write it down. Date it. Attach it to the project record. Six months later, when the predicted incident happens, that documented dissent is how you improve the process. It's not about blame. It's about organizational learning. You can't learn from experiences you haven't recorded.

**The value of the review isn't the review meeting.** The meeting is thirty to sixty minutes. The value is the artifacts it produces: the Architecture Decision Records, the risk log, the findings tracker, the documented rationale for decisions made. These artifacts outlast the project, inform future decisions, and make the enterprise smarter over time. A review that produces no durable artifacts produced no lasting value.

---

## Reviews vs. Audits: Why Conflating Them Destroys Culture

This conflation is more common than it should be, and the consequences are serious.

**Reviews are forward-looking and collaborative.** The question is: "How do we make this succeed?" The mode is consulting and advising. The posture is curious and problem-solving. The outcome should be a project team that leaves feeling better informed and more confident about risks they know how to manage.

**Audits are backward-looking and evaluative.** The question is: "Did we follow the rules?" The mode is examining and documenting. The posture is skeptical and verification-oriented. The outcome is a finding log and a compliance determination.

Both are necessary. But when review boards behave like auditors — checking boxes, looking for violations, producing findings in adversarial language — project teams stop bringing real problems to them. They bring polished decks that answer the questions they're sure will be asked, and carefully avoid surfacing the questions they're afraid to answer.

The result is a review process that produces a false sense of governance assurance. The box is checked. The risk wasn't surfaced. The incident happens anyway. The post-mortem reveals the team knew about the problem but didn't raise it because "the review board wasn't the right venue."

That failure is a culture failure, not a technical one.

The fix requires deliberate effort from review board members to signal collaborative intent. Ask "what are you most worried about?" before "are you compliant with standard X?" Spend time on genuine discussion, not just verification. When teams surface problems voluntarily, respond with help, not findings.

---

## Practical Templates: What to Actually Use

Frameworks and principles are only useful if they translate to documents people actually complete and meetings people actually run. Here's the practical toolkit:

### Architecture Decision Record (ADR)

One page. Thirty minutes to write. Mandatory for any significant architectural decision.

**Context:** What situation prompted this decision? What constraints exist? What are the forces at play?
**Decision:** What was decided? State it clearly.
**Consequences:** What becomes easier and what becomes harder as a result of this decision? What technical debt is accepted? What future options are foreclosed?
**Alternatives considered:** What else was evaluated and why was it not selected?

ADRs aren't design documents — they're decision journals. They answer "why did we do it this way?" for the engineer who joins two years from now and wonders why the system is structured the way it is. They prevent teams from relitigating settled decisions. They create institutional memory.

Michael Nygard's 2011 formalization of ADRs remains the canonical reference. The format hasn't needed to change because it got it right.

### 5-Question Security Review Checklist

For rapid security assessment in any architecture review:
1. **Authentication/authorization model** — How are users authenticated? How is authorization enforced? What's the privilege model?
2. **Data classification and protection** — What data does the system handle? How is sensitive data identified and protected at rest and in transit?
3. **Network segmentation** — What are the trust boundaries? What can reach what? Is the principle of least privilege applied at the network layer?
4. **Secrets management** — Where are credentials, keys, and certificates stored? How are they rotated? What happens if they're exposed?
5. **Logging and monitoring** — What security-relevant events are logged? Where do logs go? Who's alerted and how?

This checklist maps directly to the NIST SP 800-160 systems security engineering principles and aligns with the AWS Well-Architected Framework's Security pillar. It takes ten minutes to work through and surfaces the most common architectural security gaps.

### 30-Minute Review Format

For most architecture reviews, thirty minutes is sufficient if the team has prepared properly and distributed materials in advance.

- **5 minutes:** Context-setting. What's being reviewed, what decisions need to be made, what's already been decided.
- **10 minutes:** Architecture walkthrough. Project team presents the architecture — components, interactions, key decisions. No PowerPoint theater; a whiteboard or simple diagram is better.
- **10 minutes:** Q&A on the 5 questions. Board members work through the five questions with the team. Document answers in real time.
- **5 minutes:** Findings and next steps. What are the findings? What are the conditions for approval? Who owns what by when?

The thirty-minute format works because the review meeting is the wrong place for design discussion. Design discussion should happen before the review, with the board acting as a resource, not an audience.

### Exit Criteria

Define these before any review, not during it:

- **Approved:** All five questions answered satisfactorily. No open critical or high findings. Project may proceed.
- **Approved with conditions:** Minor findings exist with defined owners and deadlines. Project may proceed pending closure of conditions. Conditions are tracked and verified.
- **Requires re-review:** Material risks identified that require architectural changes before proceeding. Project team returns with revised approach. Timeline impact is the project team's problem to manage; it's not a reason to lower the bar.

The existence of "requires re-review" is what makes the board meaningful. If every review produces "approved" or "approved with conditions," the board isn't functioning as a review. Some projects should come back with a different approach.

---

## Bottom Line

After 25 years building and reviewing enterprise architecture, here's what I know works:

1. **Reviews only matter if they happen before irreversible decisions.** If the vendor is signed and the code is half-written, you're not reviewing — you're auditing. Move reviews to design time.

2. **The five questions are non-negotiable.** Strategic alignment, security risk, operational implications, total cost of ownership, exit strategy. Every project. Every time. No exceptions for timeline pressure.

3. **Authority without accountability is decoration.** The review board needs veto power and must exercise it. A board that has never required a project to redesign isn't doing its job.

4. **Findings that aren't tracked don't exist.** Every finding needs an owner, a deadline, and a resolution. The tracking system is what converts the review meeting into governance.

5. **Reviews are collaborative; audits are evaluative.** Conflating them destroys the culture that makes reviews work. Review boards should be the people teams want to talk to early — not dread talking to late.

6. **ADRs are the most underused tool in enterprise architecture.** Start writing them. One page, thirty minutes, massive long-term value. The decision you document today is the incident investigation that doesn't happen in two years.

Architecture reviews done right aren't overhead. They're the primary mechanism by which enterprises accumulate architectural wisdom instead of architectural debt. The investment in getting the process right pays for itself on the first major incident it prevents.

---

## References

- The Open Group. "TOGAF Standard, Version 9.2 — Architecture Governance." 2018.
- Gartner. "Building an Architecture Review Board That Works." 2022.
- NIST SP 800-160 Vol. 1. "Systems Security Engineering: Considerations for a Multidisciplinary Approach." 2022.
- Amazon Web Services. "AWS Well-Architected Framework." 2023.
- Fowler, Martin. *Patterns of Enterprise Application Architecture.* Addison-Wesley, 2002.
- Nygard, Michael. "Architecture Decision Records." 2011. https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions
- IEEE Std 42010-2011. "Systems and Software Engineering — Architecture Description." 2011.

---

#SolutionArchitecture #EnterpriseArchitecture #ArchitectureReview #TechLeadership #ITGovernance #TOGAF #CloudArchitecture #TechStrategy
