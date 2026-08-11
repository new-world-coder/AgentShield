'use strict';

const fs = require('fs');
const path = require('path');
const { hashTool, pinTool, toolFingerprint } = require('./pin');

function utcNow() {
  return new Date().toISOString();
}

class PinRegistry {
  constructor(filePath) {
    this.path = filePath || path.join(process.cwd(), '.agentshield', 'pins.json');
    this.pins = new Map();
    this.load();
  }

  static key(serverId, toolName) {
    return `${serverId}::${toolName}`;
  }

  load() {
    this.pins.clear();
    if (!fs.existsSync(this.path)) return;
    const raw = JSON.parse(fs.readFileSync(this.path, 'utf8'));
    const records = raw.pins || (Array.isArray(raw) ? raw : []);
    for (const item of records) {
      const rec = {
        server_id: item.server_id || 'default',
        tool_name: item.tool_name || item.name,
        pin_hash: item.pin_hash || item.digest,
        pinned_at: item.pinned_at || utcNow(),
        algorithm: item.algorithm || 'sha256',
        canonical_snapshot: item.canonical_snapshot || item.fingerprint || ''
      };
      this.pins.set(PinRegistry.key(rec.server_id, rec.tool_name), rec);
    }
  }

  save() {
    fs.mkdirSync(path.dirname(this.path), { recursive: true });
    const pins = [...this.pins.values()].sort((a, b) =>
      `${a.server_id}:${a.tool_name}`.localeCompare(`${b.server_id}:${b.tool_name}`)
    );
    fs.writeFileSync(
      this.path,
      `${JSON.stringify({ version: 1, updated_at: utcNow(), pins }, null, 2)}\n`,
      'utf8'
    );
  }

  listPins(serverId) {
    let pins = [...this.pins.values()];
    if (serverId) pins = pins.filter((p) => p.server_id === serverId);
    return pins.sort((a, b) =>
      `${a.server_id}:${a.tool_name}`.localeCompare(`${b.server_id}:${b.tool_name}`)
    );
  }

  pinAll(tools, { serverId = 'default', persist = true } = {}) {
    const records = [];
    for (const tool of tools) {
      const pin = pinTool(tool);
      const rec = {
        server_id: serverId,
        tool_name: pin.name,
        pin_hash: pin.digest,
        pinned_at: utcNow(),
        algorithm: pin.algorithm,
        canonical_snapshot: pin.fingerprint || toolFingerprint(tool)
      };
      this.pins.set(PinRegistry.key(serverId, pin.name), rec);
      records.push(rec);
    }
    if (persist) this.save();
    return records;
  }

  verifyTools(tools, { serverId = 'default' } = {}) {
    const findings = [];
    const liveNames = new Set();
    for (const tool of tools) {
      const name = String(tool.name || '').trim();
      if (!name) continue;
      liveNames.add(name);
      const stored = this.pins.get(PinRegistry.key(serverId, name));
      const liveHash = hashTool(tool, stored?.algorithm || 'sha256');
      if (!stored) {
        findings.push({
          server_id: serverId,
          tool_name: name,
          rule_id: 'unpinned_tool',
          severity: 'High',
          message: `Tool '${name}' has no stored pin`,
          expected_hash: '',
          live_hash: liveHash,
          taxonomy: 'MCP02'
        });
        continue;
      }
      if (liveHash !== stored.pin_hash) {
        findings.push({
          server_id: serverId,
          tool_name: name,
          rule_id: 'schema_drift',
          severity: 'Critical',
          message: `Rug pull / schema drift for '${name}'`,
          expected_hash: stored.pin_hash,
          live_hash: liveHash,
          taxonomy: 'MCP02'
        });
      }
    }
    for (const rec of this.listPins(serverId)) {
      if (!liveNames.has(rec.tool_name)) {
        findings.push({
          server_id: serverId,
          tool_name: rec.tool_name,
          rule_id: 'missing_pinned_tool',
          severity: 'High',
          message: `Pinned tool '${rec.tool_name}' missing from live tools/list`,
          expected_hash: rec.pin_hash,
          live_hash: '',
          taxonomy: 'MCP02'
        });
      }
    }
    return findings;
  }
}

/** In-memory per-user store used by API when no file path is supplied. */
const memoryStores = new Map();

function getUserStore(userId) {
  const key = String(userId || 'anonymous');
  if (!memoryStores.has(key)) {
    memoryStores.set(key, new Map());
  }
  return memoryStores.get(key);
}

function memoryList(userId, serverId) {
  const store = getUserStore(userId);
  let pins = [...store.values()];
  if (serverId) pins = pins.filter((p) => p.server_id === serverId);
  return pins;
}

function memoryPinAll(userId, tools, serverId = 'default') {
  const store = getUserStore(userId);
  const records = [];
  for (const tool of tools) {
    const pin = pinTool(tool);
    const rec = {
      server_id: serverId,
      tool_name: pin.name,
      pin_hash: pin.digest,
      pinned_at: utcNow(),
      algorithm: pin.algorithm,
      canonical_snapshot: pin.fingerprint
    };
    store.set(PinRegistry.key(serverId, pin.name), rec);
    records.push(rec);
  }
  return records;
}

function memoryVerify(userId, tools, serverId = 'default') {
  const store = getUserStore(userId);
  const temp = new PinRegistry(path.join('/tmp', `agentshield-pins-${userId}.json`));
  temp.pins = new Map(store);
  return temp.verifyTools(tools, { serverId });
}

module.exports = {
  PinRegistry,
  memoryList,
  memoryPinAll,
  memoryVerify,
  getUserStore
};
