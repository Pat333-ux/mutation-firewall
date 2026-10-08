export type RoutingScope = 'municipal' | 'state' | 'federal' | 'system';

export type RoutingDecision = 'ROUTE' | 'DROP' | 'ESCALATE';

export interface RoutingTarget {
  id: string;
  scope: RoutingScope;
  endpoint: string;
}

export interface RoutingContext {
  id: string;
  actor: {
    id: string;
    role: string;
    jurisdiction?: RoutingScope;
  };
  payload: unknown;
  preferredScope?: RoutingScope;
  timestamp: string;
}

export interface RoutingResult {
  decision: RoutingDecision;
  target?: RoutingTarget;
  reason: string;
  ruleId: string;
}

export interface RoutingRule {
  id: string;
  description: string;
  priority: number;
  evaluate: (ctx: RoutingContext) => RoutingResult | null;
}

const routingRules: RoutingRule[] = [
  {
    id: 'RT-0001',
    description: 'System actors route to system scope by default.',
    priority: 10,
    evaluate: (ctx) => {
      if (ctx.actor.role === 'system') {
        return {
          decision: 'ROUTE',
          target: {
            id: 'system-core',
            scope: 'system',
            endpoint: 'system://core',
          },
          reason: 'System actor default route.',
          ruleId: 'RT-0001',
        };
      }
      return null;
    },
  },
  {
    id: 'RT-0002',
    description: 'Preferred scope routing when explicitly provided.',
    priority: 20,
    evaluate: (ctx) => {
      if (!ctx.preferredScope) return null;

      return {
        decision: 'ROUTE',
        target: {
          id: `${ctx.preferredScope}-router`,
          scope: ctx.preferredScope,
          endpoint: `router://${ctx.preferredScope}`,
        },
        reason: 'Preferred scope routing.',
        ruleId: 'RT-0002',
      };
    },
  },
  {
    id: 'RT-0003',
    description: 'Actor jurisdiction routing when no preferred scope is set.',
    priority: 30,
    evaluate: (ctx) => {
      if (!ctx.actor.jurisdiction) return null;

      return {
        decision: 'ROUTE',
        target: {
          id: `${ctx.actor.jurisdiction}-router`,
          scope: ctx.actor.jurisdiction,
          endpoint: `router://${ctx.actor.jurisdiction}`,
        },
        reason: 'Actor jurisdiction routing.',
        ruleId: 'RT-0003',
      };
    },
  },
  {
    id: 'RT-0004',
    description: 'Unknown jurisdiction or scope escalates for review.',
    priority: 40,
    evaluate: (ctx) => {
      if (!ctx.actor.jurisdiction && !ctx.preferredScope) {
        return {
          decision: 'ESCALATE',
          reason: 'No jurisdiction or preferred scope; requires manual routing.',
          ruleId: 'RT-0004',
        };
      }
      return null;
    },
  },
];

function orderedRoutingRules(): RoutingRule[] {
  return [...routingRules].sort((a, b) => {
    if (a.priority === b.priority) {
      return a.id.localeCompare(b.id);
    }
    return a.priority - b.priority;
  });
}

export function route(ctx: RoutingContext): RoutingResult {
  for (const rule of orderedRoutingRules()) {
    const result = rule.evaluate(ctx);
    if (result) {
      return result;
    }
  }

  return {
    decision: 'DROP',
    reason: 'No routing rule matched.',
    ruleId: 'RT-DEFAULT',
  };
}

export function addRouteRule(rule: RoutingRule): void {
  routingRules.push(rule);
}

export function listRouteRules(): RoutingRule[] {
  return orderedRoutingRules();
}
