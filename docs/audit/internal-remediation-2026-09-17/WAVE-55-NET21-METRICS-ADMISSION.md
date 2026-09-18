# Wave 55 NET-21: source-fair metrics connection admission

Date: 2026-09-18. Base: `da2eb46`. Scope: the opt-in metrics HTTP listener,
one pure admission regression and this evidence note. No endpoint, response
format, consensus rule, persisted format, deployment setting or live listener
changed.

## Correction

The metrics server already limited itself to 16 concurrent workers and gave
each connection a ten-second whole-request deadline. The limit was global,
however: one address could occupy every worker with incomplete request heads,
preventing the scraper and health probe from obtaining the observability the
listener exists to provide.

Metrics admission now reserves at most four workers per normalized source IP
while retaining the existing 16-worker global ceiling. IPv4 and its
IPv4-mapped IPv6 spelling share one allowance. A single RAII guard owns both
reservations through the worker lifetime, so ordinary completion, an early
return or a panic releases both.

The saturated path retains the same small `503` response, but first makes the
socket nonblocking. Previously that write happened before worker socket
timeouts were configured. Although the response normally fits a kernel send
buffer, the accept loop no longer depends on a saturated client continuing to
read. If the immediate write cannot complete, the socket simply closes.

## Regression

`connection_admission_is_per_ip_global_and_released_by_guard` exercises the
admission helper without opening a listener. It proves that:

- four connections consume one source's allowance and its IPv4-mapped alias
  cannot obtain a fifth;
- another address retains capacity;
- dropping a guard restores the source allowance; and
- distinct addresses cannot exceed 16 workers in aggregate, with the entire
  count returning to zero after all guards drop.

Validation on this checkout:

- focused admission regression: 1 passed;
- `git diff --check`: passed.

No workspace-wide formatter or test suite was run.

## Residual

NET-21 remains **PARTIAL**. Metrics are still unauthenticated when an operator
deliberately enables a routable bind and explicitly supplies
`--allow-public-metrics`; peer counts, validator activity, lag, finality and
keystore status remain disclosed to every client that can reach that socket.
Four connections is node-local source fairness, not identity: distributed
addresses can still fill the global allowance, and multiple legitimate
scrapers behind one NAT share four slots. Firewall policy, TLS/authentication
and fleet deployment were not inspected or changed.
