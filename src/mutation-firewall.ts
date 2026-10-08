import { canonicalize, computePayloadHash, sha256 } from './canonical.js';
import { HashChainLog, type LogEntry } from './log.js';

export type MutationScope =
  | 'municipal'
  | 'state'
  | 'federal'
  | 'system'
  | 'unknown';

export type MutationType = 'create' | 'update' | 'delete' | 'execute' | 'configure';

export interface MutationActor {
  id: string;
  role: string;
  jurisdiction?: MutationScope;
}

export interface MutationTarget {
  id: string;
  scope: MutationScope;
  resourceType: string;
}

export interface MutationPayload {
  type: MutationType;
  data: unknown;
  timestamp: string;
  nonce: string;
}

export interface MutationContext {
  actor: MutationActor;
  target: MutationTarget;
  payload: MutationPayload;
  sourceSystem?: string;
  channel?: string;
}

export interface FirewallEnvelope extends MutationContext {
  payloadHash: string;
  canonicalHash: string;
}

export type FirewallDecision = 'ALLOW' | 'DENY' | 'FLAG' | 'ESCALATE';

export interface FirewallResult {
  decision: FirewallDecision;
  reason: string;
  ruleId: string;
  timestamp: string;
  envelope: FirewallEnvelope;
}

export interface FirewallRule {
  id: string;
  description: string;
  priority: number;
  evaluate: (ctx: FirewallEnvelope) => FirewallDecision | null;
}

const mutationLog = new HashChainLog();

const firewallRules: FirewallRule[] = [
  {
    id: 'R-0001',
    description: 'System-only mutations must originate from system actors.',
    priority: 10,
    evaluate: (ctx) => {
      if (ctx.target.scope === 'system' && ctx.actor.role !== 'system') {
        return 'DENY';
      }
      return null;
    },
  },
  {
    id: 'R-0002',
    description: 'Delete mutations require admin role in the same jurisdiction.',
    priority: 20,
    evaluate: (ctx) => {
      if (ctx.payload.type !== 'delete') return null;

      const sameJurisdiction =
        ctx.actor.jurisdiction &&
        ctx.actor.jurisdiction === ctx.target.scope;

      if (!sameJurisdiction || ctx.actor.role !== 'admin') {
        return 'DENY';
      }
      return null;
    },
  },
  {
    id: 'R-0003',
    description:
      'Federal scope mutations from non-federal actors are escalated for review.',
    priority: 30,
    evaluate: (ctx) => {
      if (
        ctx.target.scope === 'federal' &&
        ctx.actor.jurisdiction !== 'federal'
      ) {
        return 'ESCALATE';
      }
      return null;
    },
  },
  {
    id: 'R-0004',
    description:
      'Unknown scope or resource types are flagged for deterministic inspection.',
    priority: 40,
    evaluate: (ctx) => {
      if (
        ctx.target.scope === 'unknown' ||
        !ctx.target.resourceType ||
        ctx.target.resourceType.trim() === ''
      ) {
        return 'FLAG';
      }
      return null;
    },
  },
  {
    id: 'R-0005',
    description:
      'High-risk mutation types (configure/execute) from non-admins are flagged.',
    priority: 50,
    evaluate: (ctx) => {
      if (
        (ctx.payload.type === 'configure' || ctx.payload.type === 'execute') &&
        ctx.actor.role !== 'admin' &&
        ctx.actor.role !== 'system'
      ) {
        return 'FLAG';
      }
      return null;
    },
  },
];

function sortRulesDeterministically(rules: FirewallRule[]): FirewallRule[] {
  return [...rules].sort((a, b) => {
    if (a.priority === b.priority) {
      return a.id.localeCompare(b.id);
    }
    return a.priority - b.priority;
  });
}

export function evaluateMutation(
  ctx: MutationContext,
  rules: FirewallRule[] = firewallRules,
): FirewallResult {
  const orderedRules = sortRulesDeterministically(rules);
  const payloadHash = computePayloadHash(ctx.payload.data);
  const envelopeBody = { ...ctx, payloadHash };
  const envelope: FirewallEnvelope = {
    ...envelopeBody,
    canonicalHash: sha256(canonicalize(envelopeBody)),
  };
  const timestamp = ctx.payload.timestamp;

  for (const rule of orderedRules) {
    const decision = rule.evaluate(envelope);
    if (decision) {
      const result: FirewallResult = {
        decision,
        reason: rule.description,
        ruleId: rule.id,
        timestamp,
        envelope,
      };
      appendDecision(result, ctx);
      return result;
    }
  }

  const result: FirewallResult = {
    decision: 'ALLOW',
    reason: 'No firewall rule matched; default allow.',
    ruleId: 'R-DEFAULT',
    timestamp,
    envelope,
  };
  appendDecision(result, ctx);
  return result;
}

function appendDecision(result: FirewallResult, ctx: MutationContext): void {
  mutationLog.append({
    mutationId: ctx.payload.nonce,
    decision: result.decision,
    actorId: ctx.actor.id,
    artifactType: ctx.target.resourceType,
    reason: result.reason,
    payloadHash: result.envelope.payloadHash,
    envelopeHash: result.envelope.canonicalHash,
    timestamp: result.timestamp,
  });
}

export function mutationFirewall(ctx: MutationContext): FirewallResult {
  return evaluateMutation(ctx);
}

export function getFirewallRules(): FirewallRule[] {
  return sortRulesDeterministically(firewallRules);
}

export function addFirewallRule(rule: FirewallRule): void {
  firewallRules.push(rule);
}

export function getMutationLog(): LogEntry[] {
  return mutationLog.snapshot();
}

export function verifyMutationLog(): number {
  return mutationLog.verify();
}
