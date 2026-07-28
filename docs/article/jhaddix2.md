Prompt Injection Isn’t Going Away — Jason Haddix on the Architecture Problem Nobody Wants to Admit
In an interview on the Secure Disclosure podcast(@the Secure Disclosure) about two months ago, Jason Haddix — known for his red team and offensive security work, and more recently his research into pentesting AI systems — was asked a question every AI security researcher eventually gets: is this actually solvable, or are we permanently stuck?

Haddix has spent years building the industry’s go-to methodologies for web hacking and bug hunting — including The Bug Hunter’s Methodology, still actively maintained and cited as core reading alongside published titles like The Web Application Hacker’s Handbook. His resume includes CISO at Ubisoft, director of penetration testing at HP’s Shadow Labs, and the #1 spot on Bugcrowd’s researcher leaderboard in 2014. These days he runs Arcanum Information Security, focused on red team training and consulting.

His answer was refreshingly blunt. As long as LLMs stay on current transformer/attention architecture, there’s no real separation between instructions and data — it’s all just text to the model. If you are a developer, then you already knew that this isn't a bug that can be fixed. Its a permanent fixture in the world of AI. It’s the foundation the whole thing sits on. He pointed out that even optimistic voices in the industry — he named Dario Amodei and Sam Altman — talk about maybe reaching 98% mitigation, not elimination. And he framed that as roughly where we already sit with web security in general: imperfect, but workable.

Why the old jailbreaks stopped working

Haddix walked through the evolution: the early prompt injection era was almost a novelty — simple “ignore all previous instructions” tricks, or narrative workarounds like asking a model to explain something dangerous framed as a bedtime story from a grandmother. Cute stuff by today’s standards. He noted that those still work, but mostly on open-source or lower-safety-tuned models. On the frontier models — the ones behind tools like Claude Code or GPT-5 — that category of attack doesn’t work out of the box anymore. You have to combine techniques.

The framework he uses to think about attacks now breaks into three parts: what you’re actually trying to get the model to do, the specific technique used to attempt it, and the evasion layer needed to get past whatever’s guarding the model — safety training, a classifier, a prompt-based filter, or some combination.

Using a model to guard a model

The interviewer pushed on the current state of prompt-injection defense products, and Haddix’s answer was candid: it can feel strange using a model to defend against a model. Or a model to fight a model, whether it be triage, or something more in depth. The fact is, the people who have prayed for rain, must be content to deal with the mud.
He was careful to frame his view as an offensive researcher’s perspective, not a definitive enterprise recommendation — but from that vantage point, layered defense is what actually raises the cost of an attack. His baseline recommendation: start with a well-trained foundation model, since those already come with meaningful safety tuning baked in against common injection patterns, then layer additional defenses on top.

Why this matters for agent-based security tools

This lines up with something worth sitting with if you’re building anything agentic on top of an LLM — including tools like Halo. The instructions-vs-data problem Haddix describes isn’t unique to chatbots; it applies just as much to an agent parsing scan output, log files, or scraped web content as potential attack surface. Any place an autonomous system ingests untrusted text is a place that text could carry an instruction the model wasn’t supposed to follow.

The practical takeaway isn’t “wait for the problem to get solved” — Haddix is pretty clear it may never fully be solved under current architectures. It’s to treat prompt injection resistance the way the rest of security already treats defense: layered, assumed-imperfect, and worth the marginal cost of making an attacker’s job harder, even without a guarantee of zero failure.
