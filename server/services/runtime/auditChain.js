'use strict';

const crypto = require('crypto');
const fs = require('fs');

function canonicalJson(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

function hashPayload(payload, prevHash) {
  return crypto.createHash('sha256').update(`${prevHash}\n${payload}`).digest('hex');
}

class AuditChain {
  constructor(path = null, genesisHash = '0'.repeat(64)) {
    this.path = path;
    this.genesisHash = genesisHash;
    this._entries = [];
  }

  static load(filePath) {
    const chain = new AuditChain(filePath);
    if (!filePath || !fs.existsSync(filePath)) return chain;
    const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
    for (const line of lines) {
      chain._entries.push(JSON.parse(line));
    }
    return chain;
  }

  _lastHash() {
    if (!this._entries.length) return this.genesisHash;
    return this._entries[this._entries.length - 1].entry_hash;
  }

  append(eventType, detail) {
    const seq = this._entries.length + 1;
    const timestamp = new Date().toISOString();
    const body = { seq, timestamp, event_type: eventType, detail };
    const prevHash = this._lastHash();
    const entryHash = hashPayload(canonicalJson(body), prevHash);
    const entry = {
      seq,
      timestamp,
      event_type: eventType,
      detail,
      prev_hash: prevHash,
      entry_hash: entryHash
    };
    this._entries.push(entry);
    if (this.path) {
      fs.appendFileSync(this.path, `${JSON.stringify(entry)}\n`, 'utf8');
    }
    return entry;
  }

  verify() {
    let prev = this.genesisHash;
    for (const entry of this._entries) {
      if (entry.prev_hash !== prev) {
        return { ok: false, reason: `prev_hash mismatch at seq ${entry.seq}` };
      }
      const body = {
        seq: entry.seq,
        timestamp: entry.timestamp,
        event_type: entry.event_type,
        detail: entry.detail
      };
      const expected = hashPayload(canonicalJson(body), prev);
      if (entry.entry_hash !== expected) {
        return { ok: false, reason: `entry_hash mismatch at seq ${entry.seq}` };
      }
      prev = entry.entry_hash;
    }
    return { ok: true, reason: 'ok' };
  }
}

module.exports = { AuditChain };
