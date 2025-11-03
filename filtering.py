# filtering.py
"""
Core ATM filtering components:
 - ATMCell: simple cell model
 - HeaderRule: deny list for (VPI,VCI)
 - PayloadRule: signature-based payload matching
 - TokenBucket: per-(VPI,VCI) policer
 - ATMFilter: applies rules in order
"""

import time
from collections import defaultdict

class ATMCell:
    """Simple ATM cell representation (header + small payload)"""
    def __init__(self, vpi:int, vci:int, payload:str, is_malicious:bool=False):
        self.vpi = int(vpi)
        self.vci = int(vci)
        self.payload = str(payload)
        self.is_malicious = bool(is_malicious)
        self.timestamp = time.time()

    def header(self):
        return (self.vpi, self.vci)

class HeaderRule:
    """Denylist of (vpi, vci) pairs"""
    def __init__(self, deny_list=None):
        self.deny_list = set(deny_list) if deny_list else set()

    def check(self, cell:ATMCell) -> bool:
        """Return True if cell should be blocked by header rule"""
        return cell.header() in self.deny_list

    def add(self, vpi_vci):
        self.deny_list.add(tuple(vpi_vci))

    def remove(self, vpi_vci):
        self.deny_list.discard(tuple(vpi_vci))

class PayloadRule:
    """Signature based payload rule"""
    def __init__(self, signatures=None):
        self.signatures = list(signatures) if signatures else []

    def check(self, cell:ATMCell) -> bool:
        """Return True if any signature is found in payload"""
        for sig in self.signatures:
            if sig in cell.payload:
                return True
        return False

    def add_signature(self, signature:str):
        self.signatures.append(signature)

    def remove_signature(self, signature:str):
        self.signatures = [s for s in self.signatures if s != signature]

class TokenBucket:
    """Token bucket policer for a single flow (vpi,vci)"""
    def __init__(self, rate_tokens_per_sec:float, burst_capacity:float):
        self.rate = float(rate_tokens_per_sec)
        self.capacity = float(burst_capacity)
        self.tokens = float(burst_capacity)
        self.last_time = None

    def allow(self, now:float) -> bool:
        """Return True if token available (consume 1); else False"""
        if self.last_time is None:
            self.last_time = now
        elapsed = now - self.last_time
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_time = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

class ATMFilter:
    """
    Apply rules in this order:
      1) HeaderRule -> drop if denied
      2) Policer -> drop if token bucket denies
      3) PayloadRule -> drop if signature found
      4) forward otherwise
    """
    def __init__(self, header_rule:HeaderRule=None, payload_rule:PayloadRule=None, policer_cfg:dict=None):
        self.header_rule = header_rule if header_rule else HeaderRule()
        self.payload_rule = payload_rule if payload_rule else PayloadRule()
        # policer_cfg: dict { (vpi,vci): (rate, burst) }
        self.policers = {}
        policer_cfg = policer_cfg or {}
        for k, (r,b) in policer_cfg.items():
            self.policers[tuple(k)] = TokenBucket(r, b)

    def process(self, cell:ATMCell, now:float):
        """
        Returns a tuple (action, reason)
         - action: 'drop' or 'forward'
         - reason: 'header' | 'policer' | 'payload' | None
        """
        if self.header_rule.check(cell):
            return ("drop", "header")
        key = cell.header()
        if key in self.policers:
            allowed = self.policers[key].allow(now)
            if not allowed:
                return ("drop", "policer")
        if self.payload_rule.check(cell):
            return ("drop", "payload")
        return ("forward", None)
