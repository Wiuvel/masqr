# The identity file

`identity.json` is the **only** thing this core persists. Everything else it knows arrives over the
control interface or is measured at run time.

## Contents

| Field | What it is |
| ----- | ---------- |
| `device_id` | The device's id on Cloudflare's side; the path component of every later call. |
| `access_token` | Bearer token for those calls. **A credential.** |
| `license` | Empty for a free account; carried so an account with a plan keeps it across a re-read. |
| `private_key_sec1` | The MASQUE private key, SEC1 DER in base64. Signs the client certificate. **A credential.** |
| `endpoint_public_key_pem` | The endpoint's public key. The TLS handshake is verified against this rather than against a certificate authority. |
| `assigned_v4`, `assigned_v6` | The addresses the tunnel carries — the inside of the tunnel, not the machine's. |
| `endpoint_h2_v4` | Where the HTTP/2 data path dials. A literal address, so bringing the tunnel up needs no DNS. |
| `endpoint_v4`, `endpoint_v6` | Where HTTP/3 goes: the peer endpoint registration returned, with its placeholder port dropped. Absent from a file written before they were kept, and then HTTP/3 dials the known anycast address — one address for every consumer device, so an older file loses nothing and is not registered again. |

A missing file is the ordinary first-run case, not a failure: `register` and `up` both create one.

## It is a real credential

The file identifies a real device registered with Cloudflare. It never belongs in a repository, and
`.gitignore` excludes it. An application that ships this core should keep it somewhere per-user and
per-machine — the application that does keeps it under `%APPDATA%`.

Deleting it is not destructive in any lasting sense: the next start registers a fresh device. It does
leave the old one behind on Cloudflare's side, which is the reason registration is not done casually.

## The format is this core's own

Nothing but this core reads it. It is deliberately not another implementation's configuration shape
— but the private key uses the same SEC1 encoding, so an identity is portable between
implementations that use that encoding.

## When it is replaced

`warp::Enrolment` replaces a device the endpoint has stopped accepting. Deliberately narrow:

- the sign is a **4xx from the endpoint** and nothing else. A refusal carried by a dead line belongs
  to the network, which is what the retry schedule allows for;
- and not sooner than **ten minutes** after the last registration, so a flapping link cannot create
  one device per flap.

After replacing it the core **stops** rather than carrying on: new credentials come with new
addresses inside the tunnel, and changing a live interface's address underneath a running core is a
great deal of care for an event that happens approximately never. Whatever supervises the core starts
it again, and the new start uses the new device.

Without this, a device Cloudflare has invalidated leaves the core presenting the same rejected
credentials forever, failing identically every few seconds, with nothing in the loop able to notice
that the thing being retried is the one thing that cannot succeed.
