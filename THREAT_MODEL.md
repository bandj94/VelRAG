# Threat model

## What the assistant does
Vel is the internal helpdesk assistant at Velmora Systems, a fictional 600-person software company. Employees ask it IT and HR questions, and it answers from company documents with citations. HR staff and IT admins also use it to look up their restricted documents: salary bands and investigations for HR; service accounts, servers, and break-glass access for IT. When asked, it can email a user a summary at their own address.

## Assets (ranked)
1. **IT-admin documents:** service account keys, the break-glass passphrase, admin server names, and the privileged access list. A leak could hand an attacker Velmora's infrastructure.
2. **The email tool and the system prompt** (roughly equal):
   - The email tool can carry data out of the company or send messages that look like they come from Vel.
   - The system prompt holds internal rules and the routing code, which help an attacker plan other attacks.
3. **HR documents:** salaries, performance plans, and investigations. A leak harms privacy and trust, but it gives an attacker no access to systems.

Also in scope, not ranked against the four above:
- **Availability:** Vel staying responsive for everyone.
- **The models and packages Vel runs on:** if one is swapped or tampered with, nothing Vel says can be trusted.
- **Fine-tuning data:** if Velmora ever fine-tunes a model on helpdesk tickets, the tickets become a way to plant behavior.

## Attackers and what they want

### Insider: a regular employee
Signed in with the employee role. They want what their role can't see on the IT side:
- **Admin keys or the break-glass passphrase**, to get access beyond their role.
- **Admin server names**, to poke around or prepare something bigger.

They can ask Vel directly, try to talk it into ignoring its rules, dig for its hidden instructions, or flood it with heavy requests.

Secondary goal: HR data. It ranks last, but it's still tested for leaks.

### Content contributor: someone who can get a document into the knowledge base
They can't query Vel as an HR or IT-admin user, but they can get a document indexed in two ways:
- **Imported vendor documentation:** it's pulled in automatically, so compromising a vendor is enough. This attacker may have no Velmora account at all.
- **Shared-drive uploads:** anyone with drive access can add a file that gets indexed. This attacker usually has a low-privilege account.

Main goal: steal data through Vel. A planted document tells Vel to carry secrets out of an HR or IT-admin user's session: through a link or image in the answer, through script in the answer, or through the email tool.

Secondary goals, using the same access:
- Phishing links in Vel's answers.
- False information that changes Vel's answers.
- Documents that make Vel waste resources.

### Upstream attacker (supply chain)
Compromises something Vel depends on before it reaches Velmora: a model file, a model repository, or a software package. Goal: get Vel running weights or code that Velmora didn't approve.

### Data poisoner (fine-tuning)
Can get examples into fine-tuning data, for example by filing helpdesk tickets. Goal: plant a hidden trigger phrase that makes a fine-tuned model push the attacker's link or give unsafe advice.

## How untrusted text gets in
Only the system prompt is trusted. Vel follows the user's requests within the system rules, but a signed-in employee can still try to manipulate it. Everything else is data, never instructions:
- **Retrieved documents:** written by many people, including vendors and anyone with shared-drive access.
- **Email tool results:** a tool's output is data, not instructions.
- **Model files and packages:** they come from outside sources and must match what Velmora approved.
- **Fine-tuning data**, if Velmora ever fine-tunes: tickets come from anyone who can file one.

Ways data gets out:
- **The browser:** the UI renders Vel's answers as markdown and raw HTML. A link or image in an answer can make the user's browser contact an outside server, and raw HTML can run script in the user's browser.
- **The email tool:** it can send whatever Vel has seen to any address it's given.

## Worst realistic outcome
Admin keys leak, and an attacker uses them to get into Velmora's systems.

## Out of scope
- **Real authentication and authentication bypass:** roles are simulated in this lab.
- **Images and other non-text input.**
- **Attacks on Ollama, Chroma, or the host machine.**
- **Real compromised packages or models:** the supply-chain checks tamper with copies on purpose.
- **Model extraction**, which OWASP's 2026 list files under Unbounded Consumption.
- **Anything that leaves this machine.**
