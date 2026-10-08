import { describe, expect, it } from 'vitest';
import {
  addRouteRule,
  listRouteRules,
  route,
  type RoutingContext,
  type RoutingRule,
} from '../src/routing';

const context = (overrides: Partial<RoutingContext> = {}): RoutingContext => ({
  id: 'request-1',
  actor: { id: 'actor-1', role: 'citizen' },
  payload: {},
  timestamp: '2026-01-01T00:00:00.000Z',
  ...overrides,
});

describe('deterministic routing', () => {
  it('lists built-in rules by priority', () => {
    expect(listRouteRules().map(({ id }) => id)).toEqual([
      'RT-0001',
      'RT-0002',
      'RT-0003',
      'RT-0004',
    ]);
  });

  it('routes system actors to system core before other routes', () => {
    expect(
      route(
        context({
          actor: { id: 'system', role: 'system', jurisdiction: 'federal' },
          preferredScope: 'state',
        }),
      ),
    ).toMatchObject({
      decision: 'ROUTE',
      ruleId: 'RT-0001',
      target: {
        id: 'system-core',
        scope: 'system',
        endpoint: 'system://core',
      },
    });
  });

  it('routes to an explicitly preferred scope', () => {
    expect(route(context({ preferredScope: 'state' }))).toMatchObject({
      decision: 'ROUTE',
      ruleId: 'RT-0002',
      target: {
        id: 'state-router',
        scope: 'state',
        endpoint: 'router://state',
      },
    });
  });

  it('falls back to actor jurisdiction', () => {
    expect(
      route(
        context({
          actor: { id: 'actor-1', role: 'citizen', jurisdiction: 'municipal' },
        }),
      ),
    ).toMatchObject({
      decision: 'ROUTE',
      ruleId: 'RT-0003',
      target: { scope: 'municipal', endpoint: 'router://municipal' },
    });
  });

  it('escalates when neither preferred scope nor jurisdiction is present', () => {
    expect(route(context())).toMatchObject({
      decision: 'ESCALATE',
      ruleId: 'RT-0004',
    });
  });

  it('sorts and evaluates custom rules deterministically', () => {
    const rule: RoutingRule = {
      id: 'RT-CUSTOM-TEST',
      description: 'Custom fallback',
      priority: 50,
      evaluate: () => ({
        decision: 'DROP',
        reason: 'Custom fallback',
        ruleId: 'RT-CUSTOM-TEST',
      }),
    };
    addRouteRule(rule);
    expect(listRouteRules().at(-1)?.id).toBe(rule.id);
    expect(route(context({ actor: { id: 'actor-1', role: 'citizen' } }))).toMatchObject({
      decision: 'ESCALATE',
      ruleId: 'RT-0004',
    });
  });
});
