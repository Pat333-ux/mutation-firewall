import { describe, expect, it } from 'vitest';
import {
  addFirewallRule,
  evaluateMutation,
  getMutationLog,
  getFirewallRules,
  mutationFirewall,
  verifyMutationLog,
  type FirewallRule,
  type MutationContext,
} from '../src/mutation-firewall';
import { computePayloadHash } from '../src/canonical';

const context = (overrides: Partial<MutationContext> = {}): MutationContext => ({
  actor: { id: 'actor', role: 'citizen', jurisdiction: 'municipal' },
  target: { id: 'target', scope: 'municipal', resourceType: 'record' },
  payload: {
    type: 'update',
    data: {},
    timestamp: '2026-01-01T00:00:00.000Z',
    nonce: 'nonce',
  },
  ...overrides,
});

describe('mutation firewall', () => {
  it('sorts built-in rules by priority', () => {
    expect(getFirewallRules().map(({ id }) => id)).toEqual([
      'R-0001',
      'R-0002',
      'R-0003',
      'R-0004',
      'R-0005',
    ]);
  });

  it('hashes the envelope and appends a deterministic hash-chain entry', () => {
    const ctx = context();
    const result = mutationFirewall(ctx);
    const entries = getMutationLog();
    const entry = entries.at(-1)!;

    expect(result.timestamp).toBe(ctx.payload.timestamp);
    expect(result.envelope.payloadHash).toBe(computePayloadHash(ctx.payload.data));
    expect(result.envelope.canonicalHash).toMatch(/^[a-f0-9]{64}$/);
    expect(entry).toMatchObject({
      mutationId: ctx.payload.nonce,
      decision: 'ALLOW',
      actorId: ctx.actor.id,
      artifactType: ctx.target.resourceType,
      payloadHash: result.envelope.payloadHash,
      envelopeHash: result.envelope.canonicalHash,
      timestamp: ctx.payload.timestamp,
    });
    expect(verifyMutationLog()).toBe(-1);
  });

  it('binds a supplied previous hash into the envelope without replacing the audit chain', () => {
    const ctx = context();
    const previousAuditHash = getMutationLog().at(-1)?.logHash;
    const suppliedPreviousHash = 'a'.repeat(64);
    const result = mutationFirewall(ctx, suppliedPreviousHash);
    const entries = getMutationLog();
    const entry = entries.at(-1)!;

    expect(result.envelope.previousHash).toBe(suppliedPreviousHash);
    expect(
      mutationFirewall(ctx).envelope.canonicalHash,
    ).not.toBe(result.envelope.canonicalHash);
    expect(entry.previousLogHash).toBe(
      previousAuditHash ?? '0'.repeat(64),
    );
    expect(verifyMutationLog()).toBe(-1);
  });

  it('denies system-scope mutations from non-system actors', () => {
    const result = mutationFirewall(
      context({ target: { id: 'target', scope: 'system', resourceType: 'config' } }),
    );
    expect(result).toMatchObject({ decision: 'DENY', ruleId: 'R-0001' });
    expect(Number.isNaN(Date.parse(result.timestamp))).toBe(false);
  });

  it('denies deletes unless an admin shares the target jurisdiction', () => {
    const deleteContext = context({
      payload: {
        type: 'delete',
        data: {},
        timestamp: '2026-01-01T00:00:00.000Z',
        nonce: 'nonce',
      },
    });
    expect(evaluateMutation(deleteContext).decision).toBe('DENY');
    expect(
      evaluateMutation({
        ...deleteContext,
        actor: { ...deleteContext.actor, role: 'admin' },
      }).decision,
    ).toBe('ALLOW');
  });

  it('escalates federal mutations from non-federal actors', () => {
    const result = mutationFirewall(
      context({
        target: { id: 'target', scope: 'federal', resourceType: 'record' },
      }),
    );
    expect(result).toMatchObject({ decision: 'ESCALATE', ruleId: 'R-0003' });
  });

  it('flags unknown scopes and high-risk mutations from non-admins', () => {
    expect(
      evaluateMutation(
        context({
          target: { id: 'target', scope: 'unknown', resourceType: 'record' },
        }),
      ).decision,
    ).toBe('FLAG');
    expect(
      evaluateMutation(
        context({
          payload: {
            type: 'execute',
            data: {},
            timestamp: '2026-01-01T00:00:00.000Z',
            nonce: 'nonce',
          },
        }),
      ).decision,
    ).toBe('FLAG');
  });

  it('evaluates custom rules in deterministic priority and id order', () => {
    const evaluated: string[] = [];
    const rules: FirewallRule[] = [
      {
        id: 'later',
        description: 'Later rule',
        priority: 1,
        evaluate: () => {
          evaluated.push('later');
          return 'DENY';
        },
      },
      {
        id: 'earlier',
        description: 'Earlier rule',
        priority: 1,
        evaluate: () => {
          evaluated.push('earlier');
          return 'FLAG';
        },
      },
    ];

    expect(evaluateMutation(context(), rules)).toMatchObject({
      decision: 'FLAG',
      ruleId: 'earlier',
      reason: 'Earlier rule',
    });
    expect(evaluated).toEqual(['earlier']);
  });

  it('adds custom rules to the default rule set', () => {
    const rule: FirewallRule = {
      id: 'R-CUSTOM-TEST',
      description: 'Test rule',
      priority: 60,
      evaluate: () => 'DENY',
    };
    addFirewallRule(rule);
    expect(getFirewallRules().some(({ id }) => id === rule.id)).toBe(true);
  });
});
