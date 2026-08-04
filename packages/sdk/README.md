# Warden TypeScript SDK

Use Warden at the point where your service loads an MCP tool. The check is automatic and fails closed when a certificate or policy does not allow the tool.

```ts
import { Warden } from '@warden/sdk';

const warden = new Warden({ apiKey: process.env.WARDEN_API_KEY });

export async function loadTool(toolUrl: string) {
  await warden.verifyOrThrow(toolUrl);
  return connectToTool(toolUrl);
}
```

`verify()` returns a machine-readable decision for pipeline reporting. `verifyOrThrow()` raises `ToolNotTrustedError` unless the decision is `allow`.

## Scoped keys

The bootstrap key can create narrower runtime keys. The raw key is returned once; store it in a secret manager.

```ts
const runtimeKey = await warden.createApiKey('production-agent', ['verify:read']);
```

Available scopes: `verify:read`, `scan:write`, `decision:write`, `certificate:write`, `webhook:manage`, and `keys:manage`.

## Revocation webhooks

```ts
const subscription = await warden.registerWebhook('https://example.com/warden-events');
const deliveries = await warden.listWebhookDeliveries(subscription.id);

// In the receiving handler, after verifying X-Warden-Signature:
warden.handleRevocationEvent(event.data.certificate_id);
```
