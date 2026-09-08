# Proposed private-accounting acceptance cases

These are unexecuted cases for a controller that does not exist yet. They specify the [candidate reservation/endorsement policy](../../studies/private-accounting-contract.md), not proof of the simulator's directional message counters. Review the observable meanings before translating them into executable tests.

| Case | Given / action | Required result |
|---|---|---|
| A01 — stable allocation | Reconnect, add a passkey, change the certified chat key, or reuse an old client snapshot | The same stable account receives no second initial `n` and cannot select a fresh allocation |
| A02 — concurrent reservation | Many distinct blinded requests race for a quota of three | At most three new signatures are committed; available units cannot go negative |
| A03 — interrupted issuance | A signature is committed but its response is lost; retry the same request | Return the same signature with one total reservation; a different request consumes another unit |
| A04 — unissued carryover | Quota three; two signatures issued; next base grant two | Next quota is three, regardless of whether those issued tokens were redeemed |
| A05 — no invented refunds | All three units were issued; a client claims rejection, cancellation, transport failure or loss | No refund from that assertion; next quota is the next grant only |
| A06 — cap and expiry | Many inactive epochs pass, or rollover races old issuance/spending | Unissued quota stays capped; old and new usable permit epochs do not overlap; settlement runs once |
| A07 — neutral redemption | A permit is redeemed or its winning claim retries repeatedly | One distinct global spend; no account's sent/received/delivered or maturity state changes from redemption alone |
| A08 — post-spend client failure | The recipient spends successfully, then cannot persist or expose its joined state | Server still knows only the spend; no delivery claim or automatic account refund is manufactured |
| A09 — unsolicited inbound | Strangers approach, are declined or blocked, or send unsolicited endorsements | No recipient reservation debit or negative standing; an inactive target gains no automatic maturity |
| A10 — two required observations | Target explicitly claims activity and receives one new valid endorsement in the same rule epoch | At most one maturity step for that epoch, affecting a later bounded grant |
| A11 — no maturity banking | Many endorsements and repeated claims arrive in one epoch; later epochs are idle | One current step, no steps carried into later idle epochs; claims alone and endorsements alone earn none |
| A12 — free responder path | A member has no remaining reservation units but responds to an established conversation and claims an endorsement | Replies require no new permit; lack of own reservations does not disqualify the activity claim |
| A13 — proof replay | Reuse an accepted acknowledgement after a checkpoint, epoch, reconnect or process change | No new endorsement flag or maturity; lifetime nullifier uniqueness remains intact |
| A14 — honest collusion result | Qualified distinct members endorse and claim without a real conversation | The supported endorsement policy may award bounded maturity; tests must not label this a proven sincere reply |
| A15 — bearer pooling | Several accounts transfer their valid permits to one visible inviter | Own-account issuance caps remain enforced, but concentration is possible; only the total minting/spend bound is asserted |
| A16 — group fan-out | Invite 99 new recipients through compliant cmsg Inbox paths | Each recipient uses its own locally generated redemption claim and distinct successful permit spend; one permit cannot authorize 99 independent claims |
| A17 — atomic endorsement activity | Crash or concurrent replay occurs between proof validation, nullifier insertion and rule activity update | Exactly one durable endorsement event; no lost marker after an unreplayable proof and no double maturity |
| A18 — atomic settlement | Crash at each step of closing an epoch, reading unissued quota, retiring old allocation and creating the next | Resume one transition with neither reset allowance nor lost/doubled carryover |
| A19 — unsupported counters | A client submits peer IDs, pair hashes, alleged message counts or a delivery assertion | None become trusted rule evidence; outputs expose reservations and endorsements without relabeling them as sent/received |
| A20 — trace and schema boundary | Inspect issuance, redemption and acknowledgement payloads/state separately | Issuance can identify its allocation; redemption contains no allocation/account/recipient/group ID; acknowledgement identifies only its target, with no content or contact graph |

The controller's activity claim is a protocol action, not a requirement for a new user-facing prompt. Its client integration may automate it during an authenticated session, provided the account explicitly authorizes that capability and passive third-party endorsements cannot impersonate it.

The local first-contact/known-contact history and blocks stay in cmsg's encrypted recipient state. Tests of this candidate cannot certify that a modified malicious client follows those local rules. A global sent/received balance test and a strict nontransferable per-visible-ID outreach test remain unsupported requirements, not tests that should be weakened until they pass.
