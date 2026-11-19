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
  - gets a time-limited admin session, usable only from the admin console, never by an assistant's OAuth token;
  - every call in it is audited with the session id and reason, and the user sees it on their own dashboard ("The site admin accessed `raven` on Nov 19 for: …").

  Each admin session is a server-side record bound to the admin account, the browser session that opened it, the device ids it names, and a fixed expiry: 30 minutes by default, at most 4 hours from the moment it opened, never extended. It can be ended early by the admin, by the user (**End admin access** on their dashboard) or by the admin signing out. Every admin action is a POST carrying the session's CSRF token, as dashboard changes are now.

  The user is told after the fact, not asked first, so the admin can troubleshoot a device whose owner is unavailable. A user may switch on **Require my approval for admin access** in their Settings; the admin's request then waits until they approve it. With that switched on there is no override in the application. An emergency override, if ever wanted, is a separate feature with its own design.

  This is a guarantee about the application, not about the machine it runs on. Someone with root on the gateway server can read the state files, change the code or edit the audit log, so the hosted privacy notice says that the operator of the server holds that power (see Decisions).
- **Account lifecycle:** invite, suspend, remove.
  - **Suspend** blocks sign-in, ends the account's dashboard sessions and any admin session on its devices, and makes every call on its devices refuse, including calls with OAuth access or refresh tokens that have not expired: the check is made on every request, not when a token is issued. The devices stay connected but serve no calls. Unsuspending restores the retained grants unchanged.
  - **Remove** revokes every OAuth client grant, access token and refresh token the account approved, ends its sessions and any admin session on its devices, and quarantines its devices: they stay enrolled (same device keys) but refuse every call until the admin transfers them to another account or deletes them. Nothing is restored if the same person is invited again.

### User accounts (seats)

- **Created only by invitation** at first. The admin issues an invite for an email address; the link (`https://invite.<your domain>/…`, single use, expires in 7 days) leads to account creation. Before the account is created, the page shows a short privacy notice that the user must accept (see Decisions). Sign-in is either:
  - **Continue with Google** (OpenID Connect: scopes `openid email` only, no offline access, so the gateway stores no Google tokens). The Google account's verified email must match the invite, so a forwarded link is useless to anyone else. The account is keyed on Google's permanent user id (`sub`), not the email, which can change.
  - **Email and password.** Here the invite link is a bearer credential: whoever opens it first can create the account, and possessing it does not prove the email address belongs to them. Until the gateway can send mail, the admin delivers it over a channel they trust (in person, or a message the invitee alone reads), and the account is marked *email unverified*. When mail sending exists, a password account must confirm a code sent to the address before it is verified. Passwords are stored as scrypt hashes, as the owner passphrase is now. A forgotten password is reset by the admin issuing a new reset link, also a bearer credential.
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
- Acceptance tests:
  - migration of a real single-owner state file, and of a file with several clients and grants, is idempotent and leaves a backup;
  - a user account cannot approve consent or activation, by page or by direct POST;
  - invites expire, work once, and are invalidated by a newer one; a Google sign-in whose verified email differs from the invite is refused; a password account created from an invite is marked *email unverified*;
  - Google ID token checks: bad signature, wrong `iss` or `aud`, expired, wrong nonce, and `email_verified: false` are each refused;
  - sessions expire, are revoked by password change and **Sign out everywhere**, and user sign-in failures never lock the admin out.

### PR 2: ownership and enforcement

- Every device in the registry gets an `owner` (account id); every grant gets the account that approved it.
- **Authorization uses the device id, never its name.** Each device already has a permanent id in the registry (`dev_…`). Today OAuth grants list devices by name; PR 2 stores device ids in grants, admin sessions, ownership records and audit events, and treats names only as labels. Renaming a device changes nothing about who may use it, and a new device given an old device's name inherits nothing.
- Consent, `/activate` and the dashboard work for user accounts, each limited to the signed-in account's devices.
- Every tool call checks that the grant's account owns the device. Admin-session calls are checked against the session's devices and expiry instead. Calls to a quarantined or suspended device are refused.
- The admin's **Open as admin** session, quarantine, and **Transfer device** (moving `raven` to Raven's account is the first real use).
- **A transfer never carries permissions across, and happens as one step.** In a single state change under the registry lock, the gateway:
  1. marks the device *in transfer*, so every new call to it is refused;
  2. cancels calls waiting on it and ends sessions (`start_process`) the old owner's clients started on it, killing their processes;
  3. removes the device from every grant that names it (access and refresh tokens stay valid for the client's other devices, but no longer reach this one) and ends any admin session on it;
  4. sets the new owner and clears *in transfer*.

  If any step fails, the device stays *in transfer*, refusing every call, until the admin retries or the startup check reconciles it. The device starts with no assistant access under its new owner, who approves their own assistants. Only the device's identity (its key, name and registry scopes) moves. A command already running on the device when step 2 runs is killed, not allowed to finish.
- **Device names become unique per account**, not per gateway: two people may each have a `laptop`. Tools address a device by name within the caller's account; the admin addresses `account/name`.
- **The local static token** (`CONTEXTBRIDGE_COMPUTER_TOKEN` on 127.0.0.1:8791) reaches every device today. On a hosted gateway it is limited to the admin's own devices; it never reaches a user's device, and suspension or quarantine applies to it like any other caller.
- Acceptance tests:
  - **isolation:** one account can never list, call, approve or see usage for another's device, by name, by id or by a crafted request;
  - **immutable ids:** two accounts each with a `laptop` never reach each other's; renaming a device leaves its grants unchanged; a device enrolled with a removed device's name gets none of its grants;
  - **admin role:** without an admin session the admin's console, assistants and local token cannot call a user's device;
  - **admin sessions:** a session reaches only its named device ids; it ends at its expiry and cannot be extended; it ends when the user or admin ends it; a POST without its CSRF token is refused; with **Require my approval** on, no session opens until the user approves;
  - **transfer:** a call waiting during the transfer fails; a running `start_process` session of the old owner is killed; afterwards the old owner's access and refresh tokens are refused on that device but still work on their other devices; the new owner has no grant until approving one; a transfer interrupted after step 1 leaves the device refusing calls, and the startup check reconciles it;
  - **suspend and remove:** an unexpired access token and a refresh token are both refused while the account is suspended and work again after unsuspending; after removal they never work again; an admin session on the account's devices ends; quarantine refuses calls without deleting the device.

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

**How the migration protects the state:**
- Before changing anything it copies `oauth.json` and `devices.json` to timestamped backups, mode 0600, in the same `state` folder.
- Each file is rewritten to a temporary file and renamed into place, so a crash leaves either the old or the new version, never half of one. A version number in each file records which migrations have run, so a second run changes nothing.
- If the migration fails, the gateway refuses to start and names the backups to restore. Restoring them and starting the previous release must work; the tests cover that rollback.
- Today the state files are locked only during each write; a second gateway process on the same `state` folder is not stopped, and the dashboard merely warns about it. PR 1 adds a single-instance lock on the folder, held for the gateway's lifetime, so a second process refuses to start, and the migration takes it before running. Copied state is a different risk: two servers started from copies of the same files share a gateway id and would both accept the same devices and tokens. The VPS guide's rule stands: stop the old gateway before starting the new one, and never run both.

The migration is tested on a single-owner state file like today's and on one with several clients, grants and devices.

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
5. **Privacy notice.** Shown on the invite page and accepted before an account is created. It states:
   - that on a hosted gateway the user's commands and file contents pass through the operator's server and Cloudflare;
   - what the gateway stores about them: account details, device names and system information, assistant approvals, and an audit log of every call (tool, device, time, and paths or commands as sent, but file contents only as a size and hash), kept for a stated period (to be set; 90 days suggested);
   - that the site admin sees call counts, and can open an audited admin session on their devices that they see on their dashboard, or must approve if they choose;
   - that whoever has root access to the server itself is not bound by the application's controls and could read or alter its data and logs.
