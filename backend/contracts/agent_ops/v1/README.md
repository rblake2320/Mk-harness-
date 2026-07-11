# Mobile Adapter Contract v1

These Draft 2020-12 JSON Schemas are the standalone wire contract for
Consultant Studio Agent Operations. They cover outbound work orders, agent
pings, execution-started callbacks, completion callbacks, and failure
callbacks.

## Authentication

Every request is authenticated with these headers:

- `X-Mobile-Agent`
- `X-Mobile-Tenant`
- `X-Mobile-Timestamp`
- `X-Mobile-Nonce`
- `X-Mobile-Signature`

The signature is lowercase hexadecimal HMAC-SHA256 over the UTF-8 bytes of:

```text
UPPERCASE_METHOD\nPATH_ONLY\nTIMESTAMP\nNONCE\nLOWERCASE_SHA256_BODY_HEX
```

The JSON body is transmitted as compact UTF-8. The signature covers the exact
bytes sent, not a re-serialized object. Timestamps are Unix seconds with a
maximum absolute skew of 300 seconds. A receiver must reject a nonce reused by
the same tenant and agent within that window.

Outbound delivery may retry transient failures. The work-order `task_id` is the
idempotency key: an adapter may accept the same task and identical body again,
but must reject reuse of a task ID with different content.

The public, non-secret example in `hmac-test-vectors.json` is suitable for
cross-language conformance tests.

## Simulator

Run the simulator only for local contract testing:

```powershell
$env:MOBILE_SIMULATOR_AGENT_ID = "simulator-1"
$env:MOBILE_SIMULATOR_TENANT_ID = "00000000-0000-4000-8000-000000000001"
$env:MOBILE_SIMULATOR_DEVICE_TOKEN = "a-local-test-token"
$env:MOBILE_SIMULATOR_CONTROL_TOKEN = "a-separate-local-control-token"
$env:MOBILE_SIMULATOR_MODE = "accept"
python -m app.agent_ops.simulator
```

The process binds to `127.0.0.1:8787`. Supported deterministic modes are
`accept`, `fail_once`, `reject`, and `unsupported_actions`. The simulator is not
a PhoneClaw implementation, does not execute device actions, and does not
change `verified_on_device` evidence.
