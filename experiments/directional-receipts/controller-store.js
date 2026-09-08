/**
 * Unpublished shared-store contract. Deliberately rejecting until hosted RED.
 * Existing receipt/permit ledger internals have not been extracted or changed.
 *
 * options: {communityId,trustedPublicKey,clock,verifyAdmission,maxCohorts,
 *   maxRequestBytes,authorizationSeconds,fault?}; all authority is trusted
 * operator configuration. fault is a synchronous test-only callback at
 * fund/settle/permit-before-commit (after tentative writes) or -after-commit
 * (durably committed, before response). Existing receipt service hooks persist.
 *
 * defineOrigin(config) -> {origin,ruleConfigDigest}; config has exactly:
 * {version:1,communityId,policyDigest,origin,previousOrigin,notBefore,endsAt,
 *  graceSeconds,rules:{initialAllowance,epochGrant,carryCap,maxAuthorizedSend,
 *  maxAcknowledgedReceive},receiptCohorts:[complete public release contexts],
 *  permitContext:complete public permit context}. RSA JWK is only {kty,n,e}
 * with minimal unsigned integer encodings. Rule digest is base64url SHA256 of
 * UTF8 JSON(['cfrm.controller.origin.v1',canonical(config)]), recursively
 * sorting object keys and preserving array order. Eligibility policyDigest is
 * distinct. Seal bounded catalogs and retain cross-purpose RSA exclusion.
 *
 * origin(id) -> null | {config,ruleConfigDigest}.
 * fundInitial(proof), rollover(proof) require the actual allocation verifier;
 * -> {communityId,memberId,origin,allocationId,quota}. Snapshot the complete
 * bounded proof before async work; hash its canonical JSON for exact retry.
 * Nonce uniqueness is community/member/nonce across operations and origins.
 * Funding, consumption, fixed allocation and frontier share one transaction.
 *
 * snapshot(origin,member) -> {counters:{authorizedSend,acknowledgedReceive},
 * allocation:null|{allocationId,quota,issued},initialOrigin:null|origin,
 * fundedThrough:null|origin,settled:boolean}. After pruning, frozen summaries
 * supply the same values. Before settlement, derive totals from cohort rows.
 *
 * receiptPort(cohortId), permitPort(origin) preserve the real service ledger
 * interfaces using this store's connection. They are internal trusted ports,
 * not account-authorized client APIs. Only target-specific internal pruning
 * may follow settlement; other origins' source rows must survive.
 * write(tx=>...) is synchronous, rejects thenables, and revokes every retained
 * tx port after completion. tx.origins.define supplies the tested config seam.
 */
const unimplemented = () => { throw new Error('Accounting store write unimplemented'); };
export function openAccountingStore(_path, _options) {
  return Object.freeze({
    defineOrigin: unimplemented,
    origin: unimplemented,
    receiptPort: unimplemented,
    permitPort: unimplemented,
    fundInitial: async () => unimplemented(),
    rollover: async () => unimplemented(),
    settleAndPrune: unimplemented,
    snapshot: unimplemented,
    write: unimplemented,
    close() {},
  });
}
