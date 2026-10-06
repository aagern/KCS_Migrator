# APIv1 fixtures

Field-for-field copies of what a real KCS 2.4-generation (`/api/v1/`) endpoint
returns, captured from a live KCS 2.5.0 instance's v1 compatibility shim on
2026-10-06 and then **sanitized**.

Every key, nesting level and value *type* is preserved, because that is what the
translation tests assert on. Every value that identified real infrastructure was
replaced with an obvious placeholder:

| Field | Why it was replaced |
|---|---|
| `deploymentToken` | A live credential. It enrolls a node-agent into the instance that issued it. |
| `kcsRegistryUrl`, `kcsRegistryUsername` | Private registry location and account. |
| `clusterId`, `id`, `systemScopes[]` | Real cluster and scope identifiers. |
| `name`, `groupName` | Named after the lab's own demo policies. |

Do not refresh these by pasting a raw API response in. Sanitize first.
