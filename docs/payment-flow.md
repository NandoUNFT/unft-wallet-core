# Payment flow

Application bindings should use the reviewed high-level flow:

1. `prepare_wallet_payment(wallet, cache, request)` verifies cached ownership,
   filters confirmations, selects inputs and returns `PreparedTransaction`.
2. The UI displays every field in `TransactionReview` and retains the
   `review_id` shown for that exact proposal.
3. `PreparedTransaction::approve(review_id)` performs the explicit transition
   to `ApprovedTransaction`. A stale or altered identifier is rejected.
4. `sign_approved_transaction(wallet, approved)` signs locally and returns raw
   transaction hex, TXID and WTXID.
5. `broadcast(network, source, signed)` is optional and occurs only when the
   client has connectivity. It verifies that the server returns the locally
   calculated TXID.

The review identifier is a domain-separated SHA-256 commitment over the
unsigned transaction and its input, recipient, fee and change totals. It is
public, contains no key material and is not a substitute for displaying the
actual destination, amount and fee to the user.

`build_transaction` and `sign_transaction` remain low-level primitives for
compatibility vectors and advanced integrations. Product-facing bindings must
not expose them as the normal send flow because they do not enforce the
`PreparedTransaction -> ApprovedTransaction` transition.

No stage persists secrets or performs network access. Losing any pending or
approved transaction only requires preparing it again from the wallet and its
reconstructible cache.
