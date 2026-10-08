import { canonicalize, sha256 } from './canonical.js';

export const GENESIS_HASH = '0'.repeat(64);

export type Decision = 'ACCEPT' | 'REJECT' | 'QUEUE_FOR_APPROVAL';

export interface LogEntryBody {
  seq: number;
  mutationId: string;
  decision: Decision;
  actorId: string;
  artifactType: string;
  reason: string;
  payloadHash: string;
  envelopeHash: string;
  timestamp: string;
  previousLogHash: string;
}

export interface LogEntry extends LogEntryBody {
  logHash: string;
}

export const hashEntry = (body: LogEntryBody): string => sha256(canonicalize(body));

/** Verifies the full chain from genesis. Returns index of first bad entry or -1. */
export function verifyChain(entries: readonly LogEntry[]): number {
  let prev = GENESIS_HASH;
  for (let i = 0; i < entries.length; i++) {
    const { logHash, ...body } = entries[i]!;
    if (body.seq !== i) return i;
    if (body.previousLogHash !== prev) return i;
    if (hashEntry(body) !== logHash) return i;
    prev = logHash;
  }
  return -1;
}

/** Append-only in-memory log. Appends are serialized by being synchronous. */
export class HashChainLog {
  private entries: LogEntry[] = [];

  append(fields: Omit<LogEntryBody, 'seq' | 'previousLogHash'>): LogEntry {
    const prev = this.entries.length
      ? this.entries[this.entries.length - 1]!.logHash
      : GENESIS_HASH;
    const body: LogEntryBody = { ...fields, seq: this.entries.length, previousLogHash: prev };
    const entry: LogEntry = { ...body, logHash: hashEntry(body) };
    this.entries.push(entry);
    return entry;
  }

  snapshot(): LogEntry[] {
    return this.entries.map((e) => ({ ...e }));
  }

  verify(): number {
    return verifyChain(this.entries);
  }
}
