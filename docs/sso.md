# Single sign-on (SAML)

Argus signs people in with your company's identity provider (IdP) over SAML 2.0. Their IdP groups
decide their role: Viewer, Operator or Admin. Password sign-in stays as the break-glass path, and you
turn it off once single sign-on works. The design and its reasons are in
[ADR-0048](adr/0048-saml-sign-in.md); the controls are in the [security model](security-model.md).

Owner: `documentation-writer`, verified by `backend-engineer` and `cloud-native-platform-engineer`.

## How it works

- **Argus starts every sign-in.** **Sign in with SSO** sends the browser to the IdP, and the IdP
  posts its answer back to Argus. Argus refuses an answer it didn't ask for, so the IdP's own app
  launcher ("IdP-initiated" sign-in) doesn't work: people open Argus's address instead.
- **The answer must carry a signed assertion**, meant for Argus's own address, answering a request
  this browser started, used once. Argus doesn't sign its requests and doesn't accept encrypted
  assertions, so it holds no SAML key.
- **Users are created at their first SSO sign-in.** The username is their email address. The role
  is recomputed from their groups at every sign-in: the highest role among their groups wins, and
  someone in no mapped group is refused.
- **Removing someone at the IdP** takes effect at their next sign-in attempt, which also ends their
  open sessions, or when their session ends (12 hours at most by default). Signing out of Argus
  doesn't sign out of the IdP.
- **An SSO user is never linked to a local user** with the same email: that sign-in is refused. An
  Admin can deactivate an SSO user to keep them out even when the IdP lets them in. Their role,
  email and password come from the IdP and can't be changed in Argus.

## What your IdP needs from Argus

Create a SAML application in your IdP with these values. `https://argus.example.com` stands for your
public URL (`auth.publicUrl`, or `ARGUS_PUBLIC_URL`). Once Argus runs with SSO on, the same values are
on **Administration → Settings → Sign-in**, and in Argus's metadata at
`https://argus.example.com/api/v1/auth/saml/metadata`.

| IdP field (names vary) | Value |
| --- | --- |
| Entity ID, Audience, Identifier | `https://argus.example.com/api/v1/auth/saml/metadata` |
| ACS URL, Reply URL, Single sign-on URL | `https://argus.example.com/api/v1/auth/saml/acs` (HTTP-POST) |
| Name ID format | `persistent` or `emailAddress`. Any other format is refused (`sso-nameid`) |
| Signing | Sign the assertion, with RSA-SHA256. SHA-1 is refused |
| Encryption | Off |
| Attributes | The user's groups, and their email address unless the Name ID is the email |

From the IdP you need its **metadata XML**: its entity ID, its sign-in URL for the HTTP-Redirect
binding, and its signing certificate. Argus reads it from a file and never fetches it.

## Set it up on Kubernetes

1. **Create the metadata ConfigMap** in Argus's namespace:

   ```bash
   kubectl -n argus create configmap argus-idp --from-file=metadata.xml=./idp-metadata.xml
   ```

   **Write access to this ConfigMap, and to the chart's values, is Admin access to Argus:** whoever
   can change the IdP can choose who is Admin. Keep the namespace's write access narrow.

2. **Set the values:**

   ```yaml
   auth:
     publicUrl: https://argus.example.com
     saml:
       enabled: true
       idpMetadataConfigMap: argus-idp
       groupsAttribute: groups          # what your IdP calls the attribute
       emailAttribute: ""               # empty: the Name ID is the email
     groupRoles:
       sec-readers: viewer
       sec-team: operator
       sec-admins: admin
   ```

   The keys of `groupRoles` are the exact strings your IdP sends, compared as they are: a group name,
   or an object id on Entra ID. The chart refuses an unknown role, SAML without a map, and a public
   URL that isn't `https://host`.

3. **Upgrade, then sign in with SSO** from a private window. The ingress must serve
   `auth.publicUrl` over HTTPS ([An ingress](runbook-kubernetes.md#an-ingress)).

## Set it up on Docker Compose

1. Copy the metadata into the `saml` volume, which the API reads at `/etc/argus/saml`:

   ```bash
   docker run --rm --user 0 -v argus_saml:/saml -v "$PWD:/in:ro" --entrypoint cp \
     argus-backend:runtime /in/idp-metadata.xml /saml/metadata.xml
   ```

2. Set in `.env` (see `.env.example`):

   ```bash
   ARGUS_PUBLIC_URL=https://argus.example.com
   ARGUS_SAML_IDP_METADATA_FILE=/etc/argus/saml/metadata.xml
   ARGUS_SAML_GROUPS_ATTRIBUTE=groups
   ARGUS_SAML_GROUP_ROLES={"sec-readers": "viewer", "sec-team": "operator", "sec-admins": "admin"}
   ```

3. `docker compose up -d api`. Compose publishes the UI on loopback only, so a public address
   needs a TLS proxy in front of `127.0.0.1:8080`.

The API reads the metadata when it starts, and refuses to start on metadata without an entity ID, a
sign-in URL or a signing certificate. After you change the file, restart the API.

## Turn password sign-in off, and back on

Once SSO works for at least one Admin, turn password sign-in off: `auth.localSignIn: false`, or
`ARGUS_LOCAL_SIGN_IN=false`. Password sign-in and password changes then answer "Local sign-in is
off". Only with it off does "whoever deploys decides who is Admin" hold: while it is on, an Admin
can still create a local Admin.

If the IdP is down or misconfigured, turn it back on (`auth.localSignIn: true`), sign in as a local
admin, and fix the IdP. Argus always keeps one active local admin for this. A forgotten password is
reset with `admin-tools reset-password` ([Compose](runbook.md), [Kubernetes](runbook-kubernetes.md)).

## When a sign-in is refused

The sign-in page shows a reason. The audit log records `auth.sso.refused` with the reason code, once
per address and reason every 15 minutes.

| Reason | What it means | What to do |
| --- | --- | --- |
| `sso-no-group` | None of the user's groups is in the map | Add the user to a mapped group, or the group to `groupRoles`. Check the groups attribute's name |
| `sso-nameid` | The Name ID isn't `persistent` or `emailAddress` | Change the app's Name ID format |
| `sso-email` | No usable email address | Set the email attribute, or send the email as the Name ID |
| `sso-conflict` | The email belongs to another Argus user, often a local one | An Admin removes the email from the local user, or deletes them |
| `sso-inactive` | An Admin deactivated this user in Argus | An Admin reactivates them |
| `sso-state` | The sign-in took more than 5 minutes, began in another browser, or the browser didn't send Argus's cookie | Start again from Argus's page |
| `sso-expired` | The IdP's answer was outside its validity window | Check both clocks |
| `sso-unsolicited` | The IdP sent an answer Argus didn't ask for (IdP-initiated) | Open Argus's address and use **Sign in with SSO** |
| `sso-invalid` | The answer didn't pass the checks: signature, audience, reply URL, issuer, or more than one assertion | Compare the IdP's settings with the table above; check the metadata is current |
| `sso-busy` | Too many sign-ins at once | Try again in a moment |

## Your identity provider

Consoles change; the field names below are what to look for.

### Google Workspace

Add a custom SAML app. Set the ACS URL and Entity ID from the table. Name ID: **Primary email**, format
**EMAIL**. Under attribute mapping, add **Group membership**, choose the groups to send, and name the
app attribute, for example `groups`. Google sends group names. Turn the app on for the people who
use Argus.

### Keycloak

Create a client with the SAML protocol and Argus's entity ID as its client ID. Sign assertions on,
document signing optional, client signature required off, encryption off. Name ID format
**persistent** or **email**, with **Force name ID format** on. Add a **Group list** mapper with the
attribute name `groups` and **Full group path** off, and a **User property** mapper for `email`. The
development realm in `deploy/sso-dev/realm.json` is a working example.

### JumpCloud

Add a custom SAML application. Set the SP Entity ID and ACS URL from the table, SAMLSubject NameID
`email` with the `emailAddress` format, and signing **Assertion**. Turn on the group attribute and
name it, for example `groups`. JumpCloud sends the names of the user groups bound to the app.

### Okta

Create a SAML 2.0 app integration. Single sign-on URL is the ACS URL, Audience URI the Entity ID.
Name ID format **EmailAddress** or **Persistent**. Add a group attribute statement named `groups`,
with a filter matching the groups Argus maps. Okta sends group names.

### Microsoft Entra ID

Add an enterprise application with SAML single sign-on. Identifier (Entity ID) and Reply URL from the
table. Under Attributes & Claims, add a **group claim**. Entra sends each group's **object ID** by
default, so the keys of `groupRoles` are object IDs. The claim's name is a URI, so set
`groupsAttribute` to it, for example `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`.
Keep the default email Name ID, or set `emailAttribute` to the email claim's URI.

A user in more than 150 groups gets a link instead of a group list ("group overage"). Argus sees no
groups and refuses them. Limit the claim to the groups assigned to the application.

## Keycloak for development

The Compose profile `sso` runs a throwaway Keycloak on `http://127.0.0.1:8180` while Argus stays on
`http://localhost:8080`. They are two sites, so the IdP's answer is a real cross-site post. The realm
in `deploy/sso-dev/realm.json` has four test users:
- `alice` in `argus-admins`
- `bob` in `argus-operators`
- `carol` in `argus-viewers`
- `dave` in no group

The realm file holds no password.

```bash
export ARGUS_E2E_SSO_PASSWORD='a long throwaway password'
docker compose --profile sso up -d keycloak
docker compose --profile sso run --rm sso-setup     # sets the users' passwords, writes the metadata
export ARGUS_PUBLIC_URL=http://localhost:8080
export ARGUS_SAML_IDP_METADATA_FILE=/etc/argus/saml/metadata.xml
export ARGUS_SAML_GROUPS_ATTRIBUTE=groups ARGUS_SAML_EMAIL_ATTRIBUTE=email ARGUS_SAML_NAME_ATTRIBUTE=name
export ARGUS_SAML_GROUP_ROLES='{"argus-admins": "admin", "argus-operators": "operator", "argus-viewers": "viewer"}'
docker compose up -d api
docker compose --profile sso run --rm e2e-sso        # the SSO walk
```

Development only: never point a real install at this Keycloak.
