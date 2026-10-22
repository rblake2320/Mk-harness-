# S12 ingress telemetry follow-through

Source: `39c100e48bc047091f40ca7ba58d555139ca11cd` (not a deployment).

The actual prior web image leaked synthetic path/query, Host, User-Agent and
Referer values. `edge-privacy-web-red-v2` is the retained negative test; v1 first
corrected the expected custom-method status from 405 to the observed 400.
The first repair still produced both the new safe log and Nginx's inherited raw
access log (`edge-privacy-web-v1`). The final repair disables the HTTP-level
default and installs only the server's content-free access format.

`edge-privacy-web-v2/report.json`: Worked against image
`sha256:c5d7e49e7d0f613442498ebce2dadcb8dd9bb25fd0ff49d1777c4b3d1fe14a8c`.
SPA request 200, deliberately unavailable loopback upstream 502, malformed method
400; four safe events, no canary in stdout/stderr, 502 still visible and unknown
method normalized to OTHER. No external upstream, network creation or business
data was used. The owned container was removed. Nginx detailed runtime error logs
are deliberately disabled because they include request context; sanitized status
events and process/configuration health remain available. CI now runs this actual
image probe, not only a configuration substring check.

AWS IaC turns off legacy ALB raw access delivery and WAF request samples while
preserving WAF enforcement, aggregate CloudWatch metrics and the historical log
bucket resource. The static negative/positive test is retained in
`edge-privacy-infra-red-v1.xml` / `edge-privacy-policy-v2.xml` (five tests including
the application HTTP error sanitizer). AWS's documented field/sampling behavior
is linked from `docs/data-map.md`.

OpenTofu validation initially used the uninitialized environment, then the wrong
platform cache; a Linux provider download timed out. Reusing the existing signed
Windows AWS/random provider cache succeeded: `edge-privacy-tofu-validate-v3.json`
has zero errors and warnings. No plan, apply, cloud setting change or archived-log
deletion occurred. Source secret scan found no leaks. Checker closure remains
0/87; staging ingress qualification still needs the authorized cloud environment.
