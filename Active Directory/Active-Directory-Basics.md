# Active Directory Basics

## What is AD?
A directory service by Microsoft that lets admins manage users, computers, and other objects in a network from one central location — instead of configuring each machine by hand.

_Analogy: A corporate office with a reception desk and a registry to check you in._

## What is a DC?
A server running AD Domain Services (AD DS) that handles all authentication/authorization requests for the domain. If it's down, no one logs in.

<p align="center">
  <kbd><img width="48%" alt="image" src="https://github.com/user-attachments/assets/a5979f5a-dedc-4bee-9bfe-36a401150fc7" /></kbd>
  <kbd><img width="48%" alt="image" src="https://github.com/user-attachments/assets/45277d26-f343-48e2-a7dd-cd0103c95fa4" /></kbd>
</p>

---

## OU vs Security Group (SG)

| | OU | Security Group |
|---|---|---|
| **Purpose** | Organize objects to apply **policy** | Grant **access/permissions** |
| **Membership** | An object sits in exactly **one** OU | An object can be in **many** SGs |
| **Example** | "Sales OU" gets a GPO that blocks USB drives | "Finance-ReadOnly" group gets read access to a shared drive |

**Interview one-liner:** OUs organize *where* an object lives for policy; SGs define *what* an object can access, regardless of where it lives.

---

## Delegation
Giving a user/group limited admin rights over a specific OU or task, instead of full Domain Admin.

**Example:** Helpdesk can reset passwords only for the Sales OU — nothing more.

**Why it matters offensively:** Misconfigured Kerberos delegation (unconstrained/constrained) is a common privesc path in AD attack chains.

---

## Managing Computers & GPOs
- Computers become AD objects once domain-joined, and can sit in OUs like users.
- **GPOs** = rule sets (password policy, firewall rules, login scripts, restrictions) linked to an OU/domain/site and auto-applied to everything inside it.

---

## Kerberos Authentication — "ID card → Wristband → Ride ticket"

1. **AS-REQ/AS-REP** — Login → KDC verifies you → issues a **TGT** (your wristband for the day).
2. **TGS-REQ/TGS-REP** — Want a resource → show TGT to KDC → get a **service ticket** for just that resource.
3. **AP-REQ** — Show that service ticket directly to the resource server → access granted.

**Scenario:** Log into your laptop once (get TGT). Open a file share later — laptop shows TGT to KDC, gets a file-share-only ticket, hands it to the file server. No re-entering password per resource.

**OSCP relevance:** This ticket flow is exactly what Kerberoasting and Golden/Silver Ticket attacks abuse.

---

## NetNTLM Authentication — "Solve the riddle, don't say the password"

1. **Negotiate** — Client says "I want to log in."
2. **Challenge** — Server sends a random nonce.
3. **Response** — Client encrypts the nonce using its password hash, sends it back.
4. **Verify** — Server/DC checks the response against the expected hash → access granted/denied.

**Scenario:** A locked door asks a riddle only the real key-holder can solve. The password is never sent — only proof you know it. That's exactly why **pass-the-hash** works: you only need the hash, not the plaintext.

---

## Trees, Forests & Trusts

- **Tree** — Domains sharing a namespace, linked hierarchically (`corp.local` → `sales.corp.local`).
- **Forest** — Top-level boundary; one or more trees sharing schema/config, not necessarily a namespace.
- **Trust** — Lets users in one domain access another domain's resources.
  - **One-way** — only one side can access the other.
  - **Two-way** — both sides can access each other.
  - **Transitive** — trust flows through (A→B→C means A trusts C).
  - **Non-transitive** — stays strictly between the two domains.

**Scenario:** Company A acquires Company B, sets up a **two-way forest trust** so both sides can share resources without merging AD environments — a classic pivot point if misconfigured.

---

## References
| Topic | Link |
|---|---|
| Active Directory Basics | [tryhackme.com/room/winadbasics](https://tryhackme.com/room/winadbasics) |
