/* CODE MORS - Mesh Node Module
 * Combined Options 1, 2, and 3:
 * Option 1: Mesh Discovery
 * Option 2: Routing Algorithm  
 * Option 3: Hybrid Mode (Mesh + Relay Fallback)
 */

'use strict';

/**
 * MeshNode class - Hybrid Mesh Network Node
 */
class MeshNode {
  constructor(config = {}) {
    this.nodeId = crypto.randomBytes(16).toString('hex');
    this.mode = config.mode || 'hybrid';
    this.maxHops = config.maxHops || 3;
    this.relayUrl = config.relayUrl || 'http://localhost:7000';
    this.meshNodes = new Map();
    this.routingTable = new Map();
    this.capabilities = config.capabilities || ['voice', 'text'];
    this.lastSeen = Date.now();
  }

  // Option 1: Discovery
  async discoverNodes() {
    // Simulated discovery - in production would broadcast via mDNS/SD
    this.meshNodes.set('neighbor1', { publicKey: '02468 ace0...', lastSeen: Date.now(), capabilities: ['voice', 'text'] });
    this.meshNodes.set('neighbor2', { publicKey: '13579 bdf2...', lastSeen: Date.now(), capabilities: ['voice', 'file'] });
    console.log('[MESH] Option 1: Discovery complete -', this.meshNodes.size, 'neighbors known');
  }

  // Option 2: Routing Algorithm
  routeMessage(destNodeId, message) {
    // 1. Check direct neighbor
    if (this.meshNodes.has(destNodeId)) {
      const encrypted = this.encryptForHop(this.meshNodes.get(destNodeId).publicKey, message);
      return { ok: true, type: 'direct', hops: 1, encrypted };
    }
    
    // 2. Check routing table
    if (this.routingTable.has(destNodeId)) {
      const route = this.routingTable.get(destNodeId);
      if (route.hops <= this.maxHops) {
        return this.forwardViaRoute(route, message);
      }
      this.routingTable.delete(destNodeId);
    }
    
    // 3. Find multi-hop path
    const path = this.findMultiHopPath(destNodeId);
    if (path) return this.forwardViaPath(path, message);
    
    // 4. Fallback to hybrid mode
    return this.fallbackRelay(message);
  }

  findMultiHopPath(destId) {
    // Try 2-hop via intermediate known nodes
    for (const [n1Id, n1] of this.meshNodes) {
      for (const [n2Id, n2] of this.meshNodes) {
        if (n1Id !== n2Id && n2Id !== this.nodeId) {
          // Simple check: if n2 is closer to destination
          const n2Dist = this.xorDistance(n2Id, destId);
          if (n2Dist < 500) { // Arbitrary range
            return { hops: 2, path: [n1Id, n2Id] };
          }
        }
      }
    }
    return null;
  }

  xorDistance(a, b) {
    const numA = BigInt('0x' + a.replace(/[^0-9]/g, ''));
    const numB = BigInt('0x' + b.replace(/[^0-9]/g, ''));
    return Number(numA ^ numB);
  }

  forwardViaRoute(route, message) {
    // Simulated forwarding through route hops
    return { ok: true, type: 'multi-hop', hops: route.hops, path: route.path };
  }

  // Option 3: Hybrid Mode - Relay Fallback
  fallbackRelay(message) {
    console.log('[MESH] Hybrid: Falling back to relay server');
    return { ok: true, type: 'relay-fallback', hops: 0, note: 'Relay server used' };
  }

  encryptForHop(recipientPublicKey, message) {
    // Per-hop encryption using derived session key
    const sharedSecret = crypto.createHash('sha256').update(this.privateKey || 'default').update(recipientPublicKey).digest('hex').substring(0, 32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(sharedSecret, 'hex'), iv);
    const encrypted = Buffer.concat([cipher.update(Buffer.from(message)), cipher.finalize()]);
    return {
      iv: iv.toString('base64'),
      encrypted: encrypted.toString('base64'),
      tag: cipher.getAuthTag().toString('base64')
    };
  }

  sendHeartbeat() {
    this.lastSeen = Date.now();
    // In production: broadcast heartbeat to mesh neighbors
    console.log('[MESH] Heartbeat sent at', new Date(this.lastSeen).toISOString());
  }

  getStatus() {
    if (this.meshNodes.size === 0) return 'isolated';
    if (this.meshNodes.size < 3) return 'limited';
    if (this.meshNodes.size < 10) return 'connected';
    return 'well-connected';
  }

  getStatusReport() {
    return {
      nodeId: this.nodeId,
      mode: this.mode,
      meshNodes: this.meshNodes.size,
      routingTable: this.routingTable.size,
      maxHops: this.maxHops,
      capabilities: this.capabilities,
      lastSeen: this.lastSeen,
      status: this.getStatus()
    };
  }
}

/* EXPORT */
module.exports = { MeshNode };
