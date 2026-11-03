# OAuth state-machine pilot (R06–R09)

Run `python3 scripts/check-model.py` with Python 3 and Java installed. It downloads the pinned upstream TLC 1.7.4 release, checks its upstream SHA-1 checksum, then runs the model and a negative control in a temporary directory. The checksum is an integrity/reproducibility check, not a separate supply-chain signature.

## What is checked

`OAuth.tla` represents code/refresh issuance, expiry, atomic consumption, post-consumption rejection and refresh replacement. `OAuth.cfg` explores **two code IDs, three refresh IDs, two competing actors and capacity one per store**. Invariants:

* At most one successful consumption and grant per original token.
* No grant without prior consumption.
* No store exceeds its configured capacity.
* A consumed token is never resurrected.

The negative control deliberately leaves a consumed token live. TLC must find a `NoResurrection` counterexample. A syntax error or generic nonzero exit is not accepted as a successful negative control.

## Implementation connection

| Model action | Go boundary / executable evidence |
|---|---|
| `Issue` | `putCode`, `issue`; capacity and Hegel command-sequence tests |
| `Consume` | `consumeCode`, `consumeRefresh`; 32-consumer barrier tests |
| `Expire` | `sweepLocked`; exact expiry boundary tests with injected clock |
| `Reject` | PKCE/scope failures after consumption; refresh rejection test |
| `Grant` | Replacement `issue`; refresh rotation and capacity-failure trace |

The shared capacity-failure trace is: issue refresh A → consume A → competing issuance B fills the freed slot → replacement issuance fails → A remains consumed and one token remains live. It is represented by `Issue/Consume/Issue/Reject` and executed by `TestContractOAuthCapacityFailureTrace`. This is a manually maintained correspondence plus shared scenarios, **not machine-checked refinement of Go**.

## Assumptions and exclusions

IDs are fresh and never reused; the finite token set bounds explored issuance. Mutex operations are atomic in the model. Invalid client credentials are stuttering steps. Expiry is nondeterministic removal before consumption, not a model of wall-clock behavior. Scope/PKCE checks are abstracted to accept/reject. Signatures, parsing, network failures, persistence and distributed storage are outside this model. Successful grants in this pilot issue refresh replacements; access-only grants are outside scope.

No fairness or liveness property is claimed. Terminal states are allowed (`CHECK_DEADLOCK FALSE`) because the finite token supply can be exhausted. TLC establishes these safety properties for the configured finite state space, not for arbitrary capacities, arbitrary execution lengths, the actual Go implementation, or the whole framework.

Lean/Rocq proofs are deferred: a useful next formal investment is a stronger implementation correspondence and additional state-machine traces, rather than an unconnected theorem about a second implementation.
