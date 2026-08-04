# Warden Python SDK

Programmatic trust verification for AI tools.

```python
from warden_sdk import Warden

warden = Warden(api_key="YOUR_API_KEY")
result = warden.verify("inventory-tool.vendor.com")
if result.decision != "allow":
    raise ToolNotTrustedError(result.reason)
```

For the common runtime path, use `verify_or_raise()` immediately before connecting to a tool:

```python
warden.verify_or_raise(tool_url)
return connect_to_tool(tool_url)
```

The SDK validates cached certificate signatures before using them offline. API keys can be created with the TypeScript or Python client using narrow scopes such as `verify:read`; the plaintext key is returned only at creation time.
