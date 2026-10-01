import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv/dist/2020.js';

const api = JSON.parse(readFileSync('generated/openapi.json', 'utf8'));
const validators = new Map(Object.entries(api.paths).map(([path, value]) => [path,
  new Ajv({ strict: false }).compile(value.post.requestBody.content['application/json'].schema),
]));
const challenge = {version: 1, request: {action: 'challenge', input: {credential: [1, 2, 3]}}};
for (const [path, validate] of validators) {
  assert.equal(validate(challenge), path === '/v1/challenge');
}
const validate = validators.get('/v1/challenge');
assert.equal(validate({...challenge, version: 2}), false);
assert.equal(validate({...challenge, unknown: true}), false);
assert.equal(validate({...challenge, request: {...challenge.request, input: {credential: [256]}}}), false);
assert.equal(validate({...challenge, request: {...challenge.request, input: {credential: [], extra: 1}}}), false);
