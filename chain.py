"""Baseline permissioned blockchain: every organisation stores a FULL copy of the chain (no partitioning).
Blue Team: replace Network.add()/find() with vertical (inter-block) / horizontal (intra-block) partitioning."""
import hashlib, json, os, time
from config import DATA, NODES

def sha(x):
    return hashlib.sha256(x if isinstance(x, bytes) else x.encode()).hexdigest()

def block_hash(b):
    return sha(json.dumps({k: b[k] for k in ("index", "timestamp", "data", "prev_hash")}, sort_keys=True))

def new_block(i, data, prev, ts=None):
    b = {"index": i, "timestamp": time.time() if ts is None else ts, "data": data, "prev_hash": prev}
    b["hash"] = block_hash(b)
    return b

class Node:
    def __init__(self, name, i):
        self.name, self.path = name, os.path.join(DATA, f"node{i}.json")
        if os.path.exists(self.path):
            self.chain = json.load(open(self.path))
        else:
            self.chain = [new_block(0, {"genesis": True}, "0" * 64, ts=0)]
            self.save()
    def save(self):
        json.dump(self.chain, open(self.path, "w"), indent=1)
    def valid(self):
        for i, b in enumerate(self.chain):
            if b["hash"] != block_hash(b) or (i and b["prev_hash"] != self.chain[i - 1]["hash"]):
                return False, i
        return True, None

class Network:
    def __init__(self):
        os.makedirs(DATA, exist_ok=True)
        self.nodes = [Node(n, i) for i, n in enumerate(NODES)]
    def add(self, data):
        head = self.nodes[0].chain[-1]
        blk = new_block(head["index"] + 1, data, head["hash"])
        for n in self.nodes:
            n.chain.append(json.loads(json.dumps(blk)))
            n.save()
        return blk
    def find(self, cert_id):
        """Majority-vote lookup across nodes -> (block, agreeing_nodes)."""
        found = [b for n in self.nodes for b in n.chain if b["data"].get("cert_id") == cert_id]
        if not found:
            return None, 0
        votes = {}
        for b in found:
            hh = block_hash(b); votes[hh] = votes.get(hh, 0) + 1
        h, c = max(votes.items(), key=lambda kv: kv[1])
        blk = next(b for b in found if block_hash(b) == h)
        return (blk, c) if c > len(self.nodes) // 2 else (None, c)
    def status(self):
        out = []
        for n in self.nodes:
            ok, bad = n.valid()
            out.append({"node": n.name, "blocks": len(n.chain), "head": n.chain[-1]["hash"], "valid": ok, "bad_index": bad})
        return out
