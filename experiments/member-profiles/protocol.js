// Fail-first contract. No profile service or privacy implementation exists yet.
export function createProfileOwner() { throw new Error('Member-held profile owner is not implemented'); }
export function createProfileReader() { throw new Error('Anonymous profile reader is not implemented'); }
export function profileChallengeBytes() { throw new Error('Profile transcript codec is not implemented'); }
export function profileResponseBytes() { throw new Error('Profile response codec is not implemented'); }
export function profileProofRequest() { throw new Error('Anonymous profile proof request is not implemented'); }
