# Phase 2 starting audit

Date: 11 November 2026

## Section 2 findings

| Requirement | Already present | Missing or requiring amendment |
| --- | --- | --- |
| Control-host timing | Ansible records control UTC timestamps before collection, after the target clock probe, and after transfer. The manifest stores target clock readings, a control midpoint, and an estimated target/control offset (`orchestrator.py`, Ansible role tasks). | Add explicit half-round-trip offset uncertainty. Increase control timestamp precision so the measurement is not limited to whole seconds. |
| Target timezone | Target UTC clock readings are captured before and after collection. | Add `date +%z`, `date +%Z`, the resolved `/etc/localtime` target, and optional `/etc/timezone` contents to collector context and the schema-v2 manifest `timezone` block. |
| Lab log format | The custom `elijah` format contains the standard combined request fields plus `$request_time`, `$request_id`, and `$connection`; `nginx -T` captures it. | Add `$msec` and `$http_x_elijah_trace`; retain every existing combined and analysis field. |
| Manifest schema v2 | Schema v1 construction, signatures, structural checks, and artifact/custody verification exist. Unsupported versions are named. | Build v2 with `timezone` and `metrics`, accept both v1 and v2 during verification, and add a stored signed v1 evidence fixture proving backward compatibility. |

## Implementation constraints confirmed

Phase 1 acquisition, evidence, and custody semantics remain binding. Parsing and analysis will read evidence without modification and write only beneath `derived/`; benchmark output will live beneath `bench/`. The existing external Floci service and AWS CLI configuration are out of scope and will not be accessed.
