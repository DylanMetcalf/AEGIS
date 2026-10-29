import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { encodeCursor } from '../src/http/cursor.js';
import { createTestApp, memberClient, resetThrottle, type TestContext } from './helpers.js';

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestApp();
});
afterAll(async () => ctx.close());
beforeEach(resetThrottle);

describe('crafted pagination cursors', () => {
  it('are rejected as invalid input, never as server errors', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    const id = crypto.randomUUID();
    const urls = [
      `/api/assets?cursor=${encodeCursor({ v: 'not-a-date', i: id })}`,
      `/api/assets?sort=createdAt&cursor=${encodeCursor({ v: '99999-99-99', i: id })}`,
      `/api/integrations?cursor=${encodeCursor({ v: 'yesterday', i: id })}`,
      '/api/audit-events?cursor=9999999999999999999',
    ];
    for (const url of urls) {
      const res = await client.get(url);
      expect(res.statusCode, url).toBe(400);
    }
    // A valid name cursor is still accepted.
    const ok = await client.get(`/api/assets?sort=name&cursor=${encodeCursor({ v: 'm', i: id })}`);
    expect(ok.statusCode).toBe(200);
  });
});
