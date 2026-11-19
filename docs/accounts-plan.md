# Accounts: site admin and user accounts (plan)

Status: proposal. Nothing here is implemented yet. Statements about current behaviour were checked against `main` at commit `8bb244d`; anything described as new still needs building and testing.

Today a ContextBridge gateway has exactly one person behind it, the **owner**. `contextbridge-admin owner-init` creates a passphrase and an authenticator (TOTP) secret, and every page that approves something checks for them: the consent page, `/activate`, and the `/devices` dashboard. Every device and every assistant grant belongs to that one owner.

This plan adds **user accounts**, so that one gateway can serve several people, each controlling only their own devices and assistants, while the person who runs the gateway keeps a separate **site admin** role.

The working example: one gateway, two people. The operator (DeepSixed) has `friday`, `thanatos`, `hermes`, `omnilink` and `p70`. Raven has `raven`. Each signs in to their own dashboard and sees only their own machines. Today `raven` is on the operator's dashboard and his assistants can reach it.

## Two ways to install

| | Standalone | Hosted (VPS) |
|---|---|---|
| Who it is for | One person, on the computer they work on | An operator serving several people, around the clock |
| Gateway runs on | The user's own computer, only while it is on | A small always-on Linux server ([vps-gateway.md](vps-gateway.md)) |
| Accounts | One: the site admin is also the only user | A site admin plus user accounts |
| Local MCP clients (Claude Code, desktop agents) | Work with no extra setup | Connect through the remote endpoint |
| ChatGPT and Claude on the web | Still need a public HTTPS URL, so a tunnel such as Cloudflare's running on that computer | The VPS's tunnel |

A standalone install is today's setup with accounts switched off: nothing in this plan changes it.

**Moving from standalone to hosted** follows the existing migration in [vps-gateway.md](vps-gateway.md#6-migrate-from-an-existing-gateway): copy `devices.json` and `oauth.json` to the VPS, keep the same `remote.public_url`, and point each agent's `gateway.url` at the VPS. The gateway id and every enrolled device key carry over, so remote agents are not reinstalled or re-enrolled, and assistant approvals keep working. One machine is the exception: the computer that ran the standalone gateway served its own files as the `local` device, which has no device key. It becomes an ordinary agent, enrolled once, and assistants are approved for it again. The hosted setup guide should script this move. The setup guide should ask which one you want first, and list the VPS requirements (Linux server, a domain on Cloudflare, outbound HTTPS) before the hosted steps.

## Roles

### Site admin (root)

- **Created at first setup, on the server.** Setup runs `owner-init` and will not finish without it: a passphrase plus an authenticator code, typed back before anything is saved. The gateway already refuses to open the remote endpoint until this exists.
  - First setup stays a command on the server, never a web page. A "first visitor becomes admin" web page can be claimed by a stranger if the site goes live before setup is done.
- **Signs in with the passphrase and authenticator only**, never Google, so the admin account and recovery never depend on an outside provider. The passphrase is changed on the Settings page, as now.
- **Sees the admin console:** **Settings** (as now) and a new **Accounts** page.
- **Accounts page:** every user account (name, email, how it signs in, last seen, number of devices and assistants). Opening one shows that account's devices, endpoints and grants, and call counts per device and assistant, read-only. Individual calls (tool, device, time) are visible only inside an admin session (below).
- **Being site admin grants no access to users' devices.** Signing in to the admin console lets the admin manage accounts and read metadata (device names, online status, usage counts). It does not let the admin, or the admin's assistants, list files, run commands or do anything else on a device the admin does not own.
- **Root access is a separate, explicit step.** To troubleshoot a user's device, the admin chooses **Open as admin** on that account and:
  - enters the passphrase and a fresh authenticator code again, even if already signed in;
  - names the device or devices and gives a reason;
  - gets a time-limited admin session (30 minutes by default, at most 4 hours), usable only from the admin console, never by an assistant's OAuth token;
  - every call in it is audited with the session id and reason, and the user sees it on their own dashboard ("The site admin accessed `raven` on Nov 19 for: …").

  The user is told after the fact, not asked first, so the admin can troubleshoot a device whose owner is unavailable. A user may switch on **Require my approval for admin access** in their Settings; the admin's request then waits until they approve it.

  Root can still reach everything, but never silently and never as a side effect of being admin.
- **Account lifecycle:** invite, suspend, remove.
  - **Suspend** blocks sign-in and every call on the account's devices and grants. Unsuspending restores them unchanged.
  - **Remove** quarantines the account's devices: they stay enrolled (same device keys) but refuse every call until the admin transfers them to another account or deletes them. The removed account's grants are revoked, not kept.

### User accounts (seats)

- **Created only by invitation** at first. The admin issues an invite for an email address; the link (`https://invite.<your domain>/…`, single use, expires in 7 days) leads to account creation. Before the account is created, the page shows a short privacy notice that the user must accept (see Decisions). Sign-in is either:
  - **Continue with Google** (OpenID Connect: scopes `openid email` only, no offline access, so the gateway stores no Google tokens). The Google account's email must match the invite. The account is keyed on Google's permanent user id (`sub`), not the email, which can change.
  - **Email and password.** The invite link itself proves the email address, so no confirmation email is needed. Passwords are stored as scrypt hashes, as the owner passphrase is now. A forgotten password is reset by the admin issuing a new reset link, so the gateway needs no mail server at first.
- **Sees the dashboard that exists today**, scoped to their account: Devices, Endpoints (assistant access), Usage and Settings, showing only their own devices, assistants and calls.
- **Adds devices** with the existing one-command installers and `/activate`, signing in with their own account instead of the owner passphrase. The device belongs to whoever approves it.
- **Approves assistants** (ChatGPT, Claude) on the consent page by signing in with their own account, and can only tick their own devices.

Open public sign-up (no invite) can come later, only after everything in PR 2 is in place.

## What stays the same

- **Device identity and pairing.** Ed25519 device keys, the agent connection, heartbeats, revocation and `contextbridge-admin pair` are unchanged. Accounts change only *who approves*, not how devices authenticate.
- **Device policy wins.** A device's own `agent.yaml` still caps what anyone, admin included, can do on it.
- **OAuth for assistants.** Same endpoint, same tokens, same per-device grants; each grant now also records which account approved it.
- **Existing state is kept.** Devices, enrolled keys, OAuth clients, grants and tokens all survive the upgrade (see Migration).

## Building it in three PRs

The order matters for safety. Today, anyone who passes the approval check can approve access to every device the config allows. If a second person could sign in before devices belong to accounts, they could approve access to the operator's machines.

### PR 1: accounts and sign-in, no change to device access

- Account records in the OAuth state file: id, kind (`admin` / `user`), email, Google `sub` or password hash, created, last sign-in, suspended.
- `owner-init` creates the admin account. Existing installs: the current owner becomes the admin on first start.
- Invites, Google sign-in, email-and-password sign-in, and the Accounts page (list only).
- **User accounts can sign in but approve nothing yet.** Consent, `/activate` and the device dashboard still require the admin. A signed-in user sees "Your account is ready; devices come in the next release."
- Tests: migration of a real state file is idempotent; a user account cannot approve consent or activation; invite expiry, single use and email match; Google ID token checks (`iss`, `aud`, `exp`, nonce, signature against Google's published keys).

### PR 2: ownership and enforcement

- Every device in the registry gets an `owner` (account id); every grant gets the account that approved it.
- Consent, `/activate` and the dashboard work for user accounts, each limited to the signed-in account's devices.
- Every tool call checks that the grant's account owns the device. Admin-session calls are checked against the session's devices and expiry instead. Calls to a quarantined or suspended device are refused.
- The admin's **Open as admin** session, quarantine, and **Transfer device** (moving `raven` to Raven's account is the first real use).
- **A transfer never carries permissions across.** Transferring a device revokes every existing grant on it at once, so the old owner's assistants lose it on their next request. The device starts with no assistant access under its new owner, who approves their own assistants. Only the device's identity (its key, name and registry scopes) moves.
- **Device names become unique per account**, not per gateway: two people may each have a `laptop`. Tools address a device by name within the caller's account; the admin addresses `account/name`.
- **The local static token** (`CONTEXTBRIDGE_COMPUTER_TOKEN` on 127.0.0.1:8791) reaches every device today. On a hosted gateway it becomes an admin credential: its calls to a user's device need the same audited admin session, or it is limited to the admin's own devices.
- Tests: one account can never list, call, approve or see usage for another's device; the admin role alone cannot call a user's device; an admin session reaches only its named devices and ends on time; after a transfer the old owner's tokens are refused on that device and the new owner has no grant until approving one; quarantine refuses calls without deleting the device.

### PR 3: installation and onboarding

- First-run setup asks **Standalone or Hosted**. Hosted lists the VPS requirements (Linux server, a domain on Cloudflare, outbound HTTPS) before any step that depends on them.
- A scripted standalone-to-hosted move (above).
- Customer onboarding: invite email or link text, the first sign-in, adding the first device, connecting an assistant.
- Updates to `README.md`, `docs/vps-gateway.md` and the installers.

## Migration

On first start of PR 1, and again on PR 2, the gateway upgrades its state files in place, once:

1. The existing owner (passphrase hash and TOTP secret) becomes the admin account. Nothing about signing in changes for the operator.
2. PR 2: every existing device is assigned to the admin account, and every existing grant to the admin. Assistants keep working with no reconnect.
3. The admin then invites Raven, and transfers `raven` to her account. The operator's grants on `raven` are revoked at that moment, and Raven approves her own assistants.

Before upgrading, back up `state/oauth.json` and `state/devices.json`. The migration writes a backup of each before changing it and is safe to run twice.

## Sign-in security

These apply to user accounts; the admin keeps today's passphrase-and-authenticator rules.

- **Sessions.** A signed-in session lasts 15 minutes of activity and at most 12 hours, in an `HttpOnly`, `SameSite=Strict`, `__Host-` cookie as now. Sessions are stored server-side so they can be revoked. Changing a password, resetting it, suspending the account or the user choosing **Sign out everywhere** ends every session of that account.
- **Rate limits.** Password sign-in failures are limited per account and per client address (for example 5 per 15 minutes), counted separately from the admin's lockout so a stranger cannot lock the admin out of recovery. A locked account says so without revealing whether the email exists.
- **Passwords.** At least 12 characters, checked against a list of common passwords, stored as scrypt hashes.
- **Invite and reset links.** Random 256-bit tokens, stored only as hashes, single use, short-lived (invites 7 days, password resets 1 hour), invalidated when a newer one is issued. They are delivered by the admin (copied link) until the gateway can send mail.
- **Google sign-in.** Authorization code flow with PKCE, a `state` value and a nonce. The ID token's signature, `iss`, `aud`, `exp` and `nonce` are checked, and `email_verified` must be true.
- **Account linking.** An account is tied to one Google `sub` at creation, through an invite whose email matches the verified Google email. A later sign-in matches on `sub` only, never on email, so a changed or reassigned Gmail address cannot take over an account. Adding Google to a password account, or a password to a Google account, needs the user signed in to the account first. The admin can unlink a sign-in method but cannot sign in as the user.

## Audit

New events, in the computer audit log with the existing ones: `account_invited`, `account_created`, `account_signed_in`, `account_sign_in_failed`, `account_suspended`, `account_removed`, `device_quarantined`, `device_transferred`, `admin_session_started`, `admin_session_ended`. Tool-call events also record the `account` that owns the grant.

Sign-in failures for user accounts are counted separately from the admin's lockout, so a stranger failing Google or password sign-in cannot lock the admin out of recovery.

## Decisions

1. **Name.** The product stays **ContextBridge** (`contextbridge.app`). A commercial brand, if ever needed, is a separate legal exercise and outside this plan.
2. **Admin sessions.** 30 minutes by default, at most 4 hours. The user is told afterwards on their dashboard; a user can require approval in advance instead.
3. **Usage the admin sees.** Call counts per account, device and assistant. Individual calls are visible only inside an audited admin session, like any other root access.
4. **Who may invite.** The site admin only, while ownership enforcement (PR 2) is new. Invites are single use and expire after 7 days. Users inviting others to share a device can be considered later.
5. **Privacy notice.** Shown on the invite page and accepted before an account is created. It states that on a hosted gateway the user's commands and files pass through the operator's server and Cloudflare, that the site admin can open an audited admin session on their devices, and that the user sees every such session on their dashboard.
