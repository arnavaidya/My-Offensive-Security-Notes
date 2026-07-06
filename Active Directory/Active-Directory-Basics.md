# Active Directory Basics

## What is AD?
A directory service by Microsoft that lets admins manage users, computers, and other objects in a network from one central location — instead of configuring each machine by hand.

_Analogy: A corporate office with a reception desk and a registry to check you in._

## What is a DC (Domain Controller) ?
A server running AD Domain Services (AD DS) that handles all authentication/authorization requests for the domain. If it's down, no one logs in.

| | |
| :---: | :---: |
| <img width="100%" alt="image" src="https://github.com/user-attachments/assets/a5979f5a-dedc-4bee-9bfe-36a401150fc7" /> | <img width="100%" alt="image" src="https://github.com/user-attachments/assets/45277d26-f343-48e2-a7dd-cd0103c95fa4" /> |

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

| | |
| :---: | :---: |
| <img width="100%" alt="image" src="https://github.com/user-attachments/assets/bdf656e9-a676-4132-a908-4b8909ffa02e" /> | <img width="100%" alt="image" src="https://github.com/user-attachments/assets/c4dfcaea-eab3-4412-b28d-846f0ee5da6d" /> |

---

## Kerberos Authentication — "ID card → Wristband → Ride ticket"

**Core idea:** prove your identity once, then use tickets (not your password) for everything else. No service ever sees your actual password or hash.

**Players:**
- **Client** — you, logging in
- **KDC (Key Distribution Center)** — runs on the DC, has two parts: **AS (Authentication Server)** (verifies identity) and **TGS (Ticket Granting Service)** (issues resource tickets)
- **Service** — the file server/app you want to reach

**Flow:**

| Step | What happens | Result |
|---|---|---|
| 1. AS-REQ (Authentication Server Request) | Client sends username + timestamp encrypted with your password hash to the AS | Proves you know the password (pre-auth) |
| 2. AS-REP (Authentication Server Reply) | AS verifies it, replies with a ticket | You get a **TGT (Ticket Granting Ticket)**, encrypted with the krbtgt hash — your "wristband" (~10hrs) |
| 3. TGS-REQ (Ticket Granting Service Request) | Client shows TGT + name of the resource (SPN — Service Principal Name) to the TGS | Requesting access to a specific service |
| 4. TGS-REP (Ticket Granting Service Reply) | TGS verifies TGT, issues a ticket for that resource | You get a **Service Session Key**, encrypted with that service account's hash |
| 5. AP-REQ (Application Request) | Client hands service ticket directly to the resource server | Server decrypts with its own hash → access granted, no DC round-trip |

**Scenario:** Log into your laptop once (get TGT/wristband). Open a file share later — laptop shows TGT to KDC, gets a file-share-only ticket, hands it to the file server. No re-entering password per resource.

**Offensive relevance (why this matters for OSCP/AD attacks):**
- **AS-REP Roasting** → targets Step 2 (works if pre-auth is disabled — no password needed to request the TGT reply, crack it offline)
- **Kerberoasting** → targets Step 4 (any authenticated user can request a service ticket, then crack it offline for the service account's password)
- **Golden Ticket** → forge a TGT using a stolen krbtgt hash (fakes Step 2 entirely)
- **Silver Ticket** → forge a service ticket using a stolen service account hash (skips Steps 3–4, fakes Step 5)

<div align="center">
  <kbd style="border: 2px solid #555555; display: inline-block; padding: 4px;">
    <img src="https://github.com/user-attachments/assets/6194e1fc-47dc-4adb-9724-7e7110af6718" alt="Kerberos Authentication" width="450" />
  </kbd>
</div>

---

## NetNTLM Authentication — "Solve the riddle, don't say the password"

**Core idea:** prove you know the password by correctly responding to a random challenge — the password (or its hash) is never sent over the wire.

**Players:**
- **Client** — you, trying to log in
- **Server** — the resource you're accessing (file share, RDP, etc.)
- **DC (Domain Controller)** — verifies the response if the server is domain-joined and can't check it locally

**Flow:**

| Step | What happens | Result |
|---|---|---|
| 1. Negotiate | Client tells the server it wants to authenticate | Starts the handshake |
| 2. Challenge | Server sends back a random value (**nonce**) | A one-time puzzle only the real password-holder can solve |
| 3. Response | Client encrypts the nonce using a hash derived from the user's password, sends it back | Proves knowledge of the password without sending it |
| 4. Verify | Server (or DC, if domain-joined) checks the response against the expected hash | Access granted/denied |

**Scenario:** A locked door asks a riddle only the real key-holder can solve. The password is never sent — only proof you know it.

**Offensive relevance (why this matters for OSCP/AD attacks):**
- **Pass-the-Hash** → since the hash (not the plaintext) is what solves the riddle in Step 3, an attacker who steals the hash can authenticate without ever knowing the actual password
- **NTLM Relay** → an attacker intercepts the Challenge/Response and relays it to a different server in real-time, authenticating as the victim elsewhere
- **Responder/LLMNR poisoning** → tricks a client into sending its NetNTLM Challenge-Response to an attacker-controlled machine, which is then cracked offline

<div align="center">
  <kbd style="border: 2px solid #555555; display: inline-block; padding: 4px;">
    <img src="https://github.com/user-attachments/assets/fe23f171-a678-423a-aca8-20b76a227dfd" alt="NetNTLM Authentication" width="450" />
  </kbd>
</div>

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
