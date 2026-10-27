"""
ElasticCap: Declassification Auditor (Module 3)

Two-layer audit architecture:
  Layer 1 (Deterministic Rules): Regex-based sensitive pattern detection
    + aggregation check. No LLM overhead, 100% deterministic.
  Layer 2 (LLM Semantic Audit): For boundary cases where Layer 1 cannot
    make a definitive decision. Only triggered when needed.

Three-tier verdict:
  RED    → Direct reject (sensitive patterns detected, clear violation)
  GREEN  → Auto-issue declassification token (data is sanitized/aggregated)
  YELLOW → Escalate to human approval (boundary case)
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .budget import Budget, SinkPrivilege, SinkType
from .dag import DataNode
from .token_issuer import issue_declassification_token


@dataclass
class AuditResult:
    """Result of an audit decision."""
    verdict: str        # "GREEN" | "YELLOW" | "RED"
    reason: str
    token: Optional[str] = None  # Populated for GREEN verdicts
    # Diagnostic: why Layer-1 did NOT auto-GREEN (for E1 analysis)
    l1_aggregated: bool = False     # _is_purely_aggregated passed
    l1_target_match: bool = False   # _target_in_user_intent passed
    l1_sensitive_hit: bool = False  # Layer-1 regex caught sensitive pattern
    # P3 tightening diagnostics (v2):
    l1_disclosure_hit: bool = False      # k-anonymity / per-record disclosure rule fired
    l1_target_whitelisted: bool = False  # target within manifest-declared sink scope
    decided_by: str = "layer2-llm"       # layer1-red | layer1-green | layer2-llm | layer2-fallback
    llm_raw_verdict: Optional[str] = None  # what Layer-2 returned before the safety net


class DeclassificationAuditor:
    """Module 3: Policy audit and declassification engine.

    Does NOT participate in the main Agent's tool call path.
    Runs as a side-channel review module.
    """

    # Sensitive patterns that trigger automatic RED (Layer 1)
    SENSITIVE_PATTERNS = [
        # API keys, secrets, passwords
        r'(?:api[_-]?key|secret|password|token|credential)\s*[:=]\s*[\S]{8,}',
        # Private keys
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        # SSN-like patterns
        r'\b\d{3}-\d{2}-\d{4}\b',
        # Credit card patterns
        r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        # AWS-style access keys
        r'AKIA[0-9A-Z]{16}',
        # JWT tokens
        r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    ]

    # Tools that genuinely anonymize / sanitize or produce ONLY aggregate
    # outputs. ``summarize`` is deliberately NOT in this set — in ChainCaps
    # it is a generic "reword text" pass-through that preserves all the
    # original sensitive content, so auto-GREEN-ing on its presence would
    # create a serious leak (any read -> summarize -> exfil would be allowed).
    # Layer 2 (the LLM / mock classifier) is the right place for ``summarize``.
    SANITIZATION_TOOLS = {
        'anonymize', 'anonymize_data', 'sanitize', 'sanitize_data',
        'mask', 'redact', 'tokenize', 'pseudonymize',
        'hash', 'hash_data', 'encrypt_field',
        'aggregate', 'aggregate_stats', 'compute_stats',
        'compute_average', 'compute_median', 'compute_count',
        'group_by', 'pivot_table',
    }

    # Alias kept for clarity / inspection — same as SANITIZATION_TOOLS.
    AGGREGATION_TOOLS = SANITIZATION_TOOLS

    # ── P3 hardening (revision): minimum group size + per-record operators ──
    # A whitelisted aggregation tool is only evidence of sanitization when
    # the aggregate cannot be inverted to individual records. Two classes of
    # aggregate can: (a) small-group aggregates (group-by with n < k), and
    # (b) per-record disclosure operators (min/max/first/last/top-k), which
    # return an actual record's value regardless of group count. Both are
    # decided here in Layer-1 (deterministic, no LLM).
    MIN_GROUP_K = int(os.environ.get("ELASTICCAP_MIN_GROUP_K", "5"))
    DISCLOSIVE_OPERATORS = {
        'min', 'max', 'argmin', 'argmax', 'minimum', 'maximum',
        'first', 'last', 'head', 'tail', 'sample', 'top_k', 'topk',
        'distinct', 'unique', 'select_record', 'get_record', 'find_record',
    }
    INDIVIDUAL_LEVEL_GROUP_KEYS = {
        'name', 'full_name', 'employee', 'employee_name', 'user', 'user_id',
        'username', 'id', 'record_id', 'row_id', 'person_id', 'patient_id',
        'ssn', 'social_security_number', 'email', 'phone', 'address',
        'uuid', 'account', 'account_id', 'passport',
    }
    # Argument names that carry an explicit group size.
    GROUP_SIZE_KEYS = ('n', 'group_size', 'min_group_size', 'group_count',
                       'num_records', 'record_count')

    def __init__(self, signing_key: bytes,
                 llm_classifier: Optional[Callable] = None,
                 p3_hardening: Optional[bool] = None):
        """
        Args:
            signing_key: HMAC key for issuing declassification tokens
            llm_classifier: Optional LLM-based classifier for Layer 2.
                Takes (prompt: str) -> "GREEN" | "YELLOW" | "RED".
                If None, all Layer 2 cases fall through to YELLOW.
            p3_hardening: Whether to enforce the revised P3 rules (Layer-1
                k-anonymity gate + manifest-whitelist requirement). Defaults
                to ``ELASTICCAP_P3_HARDENING`` (on unless set to 0). The
                off setting reproduces the pre-revision behaviour for the
                adaptive-attack before/after comparison (exp8).
        """
        if p3_hardening is None:
            p3_hardening = os.environ.get(
                "ELASTICCAP_P3_HARDENING", "1").strip() != "0"
        self._signing_key = signing_key
        self._llm = llm_classifier
        self._audit_log: List[AuditResult] = []
        self.p3_hardening = p3_hardening

    def audit(self,
              sink_call,
              dependency_chain: List[DataNode],
              user_intent: str,
              manifest=None) -> AuditResult:
        """Audit a blocked sink call.

        Args:
            sink_call: The intercepted sink ToolCall
            dependency_chain: DataNodes in the dependency lineage
            user_intent: Original user request (captured from system API,
                         NOT from the Agent's context — prevents injection)
            manifest: Manifest of the sink tool (used to verify the target
                      against the manifest-declared whitelist). Optional for
                      backwards compatibility; without it the whitelist
                      check falls back to the lineage's declared budgets.

        Returns:
            AuditResult with verdict and optional declassification token
        """
        sink_content = str(sink_call.arguments)

        # ═══════════════════════════════════════════
        # Layer 1: Deterministic rules (no LLM)
        # ═══════════════════════════════════════════

        # 1a: Sensitive pattern check → RED
        for pattern in self.SENSITIVE_PATTERNS:
            if re.search(pattern, sink_content, re.IGNORECASE):
                result = AuditResult(
                    verdict="RED",
                    reason=f"Layer 1: Sensitive pattern detected matching '{pattern}'",
                    l1_sensitive_hit=True,
                    decided_by="layer1-red",
                )
                self._audit_log.append(result)
                return result

        # 1a': k-anonymity / per-record disclosure check → RED
        # An aggregate that can be inverted to individual records must never
        # be auto-declassified: this is a deterministic Layer-1 rule, so the
        # security-critical decision stays independent of the classifier.
        if self.p3_hardening:
            disclosure = self._aggregate_disclosure_violation(dependency_chain)
            if disclosure is not None:
                result = AuditResult(
                    verdict="RED",
                    reason=f"Layer 1: {disclosure}",
                    l1_disclosure_hit=True,
                    decided_by="layer1-red",
                )
                self._audit_log.append(result)
                return result

        # 1b: Aggregation-only check → GREEN
        # v2 tightening: a target must be inside the manifest-declared sink
        # scope (not merely "mentioned in the prompt") for a deterministic
        # auto-GREEN. When the scope is not declared, the case escalates to
        # Layer-2 where the same requirement is enforced with LLM review.
        is_aggregated = self._is_purely_aggregated(dependency_chain)
        target_matches = self._target_in_user_intent(sink_call, user_intent)
        if self.p3_hardening:
            target_whitelisted = self._target_in_declared_whitelist(
                sink_call, dependency_chain, manifest)
            layer1_target_ok = target_whitelisted
        else:
            # Pre-revision behaviour: intent match alone authorized Layer-1.
            target_whitelisted = False
            layer1_target_ok = target_matches
        if is_aggregated and layer1_target_ok:
            lineage_ids = [n.node_id for n in dependency_chain]
            token = issue_declassification_token(
                self._signing_key,
                self._infer_sink_privilege(sink_call),
                lineage_ids,
            )
            if self.p3_hardening:
                l1_reason = ("Layer 1: sanitized lineage (k >= "
                             f"{self.MIN_GROUP_K}) AND target within declared "
                             "sink scope")
            else:
                l1_reason = ("Layer 1 (pre-revision rule): aggregated lineage "
                             "AND target matches user intent")
            result = AuditResult(
                verdict="GREEN",
                reason=l1_reason,
                token=token,
                l1_aggregated=True,
                l1_target_match=target_matches,
                l1_target_whitelisted=target_whitelisted,
                decided_by="layer1-green",
            )
            self._audit_log.append(result)
            return result

        # 1c: Either signal alone is a *suspect* signal — escalate rather
        # than auto-allow. Fall through to Layer 2.

        # ═══════════════════════════════════════════
        # Layer 2: LLM semantic audit (boundary cases)
        # ═══════════════════════════════════════════

        # v2 safety net: a token is issued only when the data is aggregate
        # AND the target is either manifest-whitelisted or corroborated by
        # the user's original intent. Raw (non-aggregate) data can no longer
        # be declassified by naming a target in the prompt.
        def _downgrade_reason() -> str:
            if not is_aggregated:
                return ("no aggregation/sanitization in lineage "
                        "(raw data may not be declassified by intent alone)")
            return ("target not within the manifest-declared sink scope "
                    "and not corroborated by the user intent")

        if self._llm:
            prompt = self._build_audit_prompt(sink_call, dependency_chain, user_intent)
            try:
                llm_verdict = self._llm(prompt)
                if llm_verdict == "GREEN":
                    # ── Safety net ──
                    if self.p3_hardening:
                        green_ok = (is_aggregated
                                    and (target_whitelisted or target_matches))
                    else:
                        green_ok = is_aggregated or target_matches
                    if not green_ok:
                        result = AuditResult(
                            verdict="YELLOW",
                            reason=f"Layer 2 (LLM): GREEN overridden — {_downgrade_reason()}",
                            l1_aggregated=is_aggregated,
                            l1_target_match=target_matches,
                            l1_target_whitelisted=target_whitelisted,
                            decided_by="layer2-fallback",
                            llm_raw_verdict="GREEN",
                        )
                        self._audit_log.append(result)
                        return result

                    lineage_ids = [n.node_id for n in dependency_chain]
                    token = issue_declassification_token(
                        self._signing_key,
                        self._infer_sink_privilege(sink_call),
                        lineage_ids,
                    )
                    result = AuditResult(
                        verdict="GREEN",
                        reason="Layer 2 (LLM): Semantic audit passed",
                        token=token,
                        l1_aggregated=is_aggregated,
                        l1_target_match=target_matches,
                        l1_target_whitelisted=target_whitelisted,
                        decided_by="layer2-llm",
                        llm_raw_verdict="GREEN",
                    )
                elif llm_verdict == "RED":
                    result = AuditResult(
                        verdict="RED",
                        reason="Layer 2 (LLM): Semantic audit flagged violation",
                        l1_aggregated=is_aggregated,
                        l1_target_match=target_matches,
                        l1_target_whitelisted=target_whitelisted,
                        decided_by="layer2-llm",
                        llm_raw_verdict="RED",
                    )
                else:
                    result = AuditResult(
                        verdict="YELLOW",
                        reason="Layer 2 (LLM): Uncertain — escalating to human",
                        l1_aggregated=is_aggregated,
                        l1_target_match=target_matches,
                        l1_target_whitelisted=target_whitelisted,
                        decided_by="layer2-llm",
                        llm_raw_verdict="YELLOW",
                    )
            except Exception:
                result = AuditResult(
                    verdict="YELLOW",
                    reason="Layer 2: LLM audit failed — falling back to human approval",
                    decided_by="layer2-fallback",
                )
        else:
            # No LLM configured → all boundary cases go to YELLOW
            result = AuditResult(
                verdict="YELLOW",
                reason="Layer 2 not configured — escalate to human",
                l1_aggregated=is_aggregated,
                l1_target_match=target_matches,
                l1_target_whitelisted=target_whitelisted,
                decided_by="layer2-fallback",
            )

        self._audit_log.append(result)
        return result

    # ═══════════════════════════════════════════
    # Layer 1 helper methods
    # ═══════════════════════════════════════════

    def _is_purely_aggregated(self, dependency_chain: List[DataNode]) -> bool:
        """Whether the lineage reaching the sink is sanitized.

        Dispatches on the revision flag: the hardened semantics implement a
        prefix property (see :meth:`_lineage_is_sanitized`); the pre-revision
        semantics required every derived node to be an aggregation tool
        (:meth:`_legacy_purely_aggregated`, kept for the before/after
        comparison in exp8).
        """
        if not self.p3_hardening:
            return self._legacy_purely_aggregated(dependency_chain)
        return self._lineage_is_sanitized(dependency_chain)

    def _legacy_purely_aggregated(self, dependency_chain: List[DataNode]) -> bool:
        """Pre-revision rule: EVERY derived node must be an aggregate."""
        if not dependency_chain:
            return False

        def _is_agg(node: DataNode) -> bool:
            name = (node.tool_name or "").lower()
            if name in self.AGGREGATION_TOOLS:
                return True
            if name.startswith(("aggregate", "compute_", "anonymize", "sanitize",
                               "mask", "redact", "pivot")):
                return True
            return False

        derived = [n for n in dependency_chain if not n.is_source]
        if not derived:
            return False
        if not any(_is_agg(n) for n in derived):
            return False
        return all(_is_agg(n) for n in derived)

    def _lineage_is_sanitized(self, dependency_chain: List[DataNode]) -> bool:
        """Check whether the lineage reaching the sink is sanitized.

        Sanitization is a *prefix property* of the lineage: it holds for a
        node when
          * a sanitization/aggregation tool produced it (the tool itself is
            evidence of an irreversible aggregation step), or
          * every one of its parents is sanitized — downstream tools such as
            ``generate_report``, ``summarize`` or ``compose_email`` can only
            re-format data they were given, so they cannot reintroduce
            individual records that were already aggregated away.

        Source (read) nodes are raw by definition, so any lineage whose sink
        inputs still trace back to a source without an intervening
        sanitization step is NOT sanitized. This is what stops a
        ``read(raw) -> summarize -> send`` chain from being auto-declassified
        (``summarize`` alone is a content-preserving pass-through), while
        still accepting ``read(raw) -> aggregate -> report -> send``
        (sanitize-then-share).

        ``dependency_chain`` is the full ancestor closure of the sink's
        inputs, so the sink-relevant question is whether every *direct* input
        of the sink is sanitized.
        """
        if not dependency_chain:
            return False

        by_id = {n.node_id: n for n in dependency_chain}

        def _is_agg(node: DataNode) -> bool:
            name = (node.tool_name or "").lower()
            if name in self.AGGREGATION_TOOLS:
                return True
            # Allow nodes whose declared tool name explicitly indicates
            # aggregation even if not pre-listed (defensive parsing).
            if name.startswith(("aggregate", "compute_", "anonymize", "sanitize",
                               "mask", "redact", "pivot")):
                return True
            return False

        memo: Dict[str, bool] = {}

        def _sanitized(node_id: str) -> bool:
            if node_id in memo:
                return memo[node_id]
            node = by_id.get(node_id)
            if node is None:
                # Ancestor outside the resolved chain: treat as raw.
                memo[node_id] = False
                return False
            if node.is_source:
                memo[node_id] = False
                return False
            if _is_agg(node):
                memo[node_id] = True
                return True
            parents = node.source_ids
            if not parents:
                memo[node_id] = False
                return False
            result = all(_sanitized(p) for p in parents)
            memo[node_id] = result
            return result

        # The sink's direct inputs are the leaves of this ancestor closure:
        # nodes that no other chain member depends on.
        referenced = set()
        for n in dependency_chain:
            referenced.update(n.source_ids)
        sink_inputs = [n for n in dependency_chain if n.node_id not in referenced]
        if not sink_inputs:
            return False

        return all(_sanitized(n.node_id) for n in sink_inputs)

    def _aggregate_disclosure_violation(
            self, dependency_chain: List[DataNode]) -> Optional[str]:
        """Layer-1 k-anonymity gate: detect aggregates that expose records.

        Two patterns are individually disclosive no matter how the lineage
        is composed:

        1. An explicit small group (``n`` / ``group_size`` < ``MIN_GROUP_K``),
           or grouping by an individual-level key (``group_by='name'``),
           which makes a per-group average a single person's value.
        2. A per-record disclosure operator (``min``/``max``/``first``/
           ``last``/``top_k``), which returns an actual record's value.

        Returns a human-readable violation description, or ``None``.
        """
        for node in dependency_chain:
            name = (node.tool_name or "").lower()
            if name in self.DISCLOSIVE_OPERATORS:
                return (f"per-record disclosure operator '{name}' returns "
                        f"individual record values")

            args = getattr(node, "tool_args", None) or {}
            if not args:
                continue

            for key in self.GROUP_SIZE_KEYS:
                if key in args:
                    try:
                        size = int(str(args[key]).strip())
                    except (TypeError, ValueError):
                        continue
                    if size < self.MIN_GROUP_K:
                        return (f"aggregate group size {key}={size} is below "
                                f"the k-anonymity threshold k={self.MIN_GROUP_K}")

            group_key = str(args.get("group_by", "") or "").strip().lower()
            if group_key and group_key in self.INDIVIDUAL_LEVEL_GROUP_KEYS:
                return (f"aggregate groups by individual-level key "
                        f"'{group_key}' (group size cannot exceed 1 per record)")

        return None

    def _target_in_declared_whitelist(self, sink_call,
                                      dependency_chain: List[DataNode],
                                      manifest=None) -> bool:
        """Check the sink target against the manifest-declared sink scope.

        The whitelist is the set of sink privileges declared by the lineage's
        sources (resource budgets from the trusted manifest/annotation layer)
        for the requested operation. This replaces "the target is mentioned
        in the prompt" as the authorizing condition: naming an address in the
        user request must not by itself widen where data may go.

        The sink tool's own manifest is deliberately NOT used as a fallback:
        it declares which operation the tool performs (usually scope ``*``),
        not which targets the data's owner authorized. With no declaration
        available the target is treated as not whitelisted and the case
        escalates to Layer 2.
        """
        requested = self._infer_sink_privilege(sink_call)
        if requested is None:
            return False

        declared: List[SinkPrivilege] = []
        for node in dependency_chain:
            budget = getattr(node, "budget", None)
            if budget is None:
                continue
            for p in budget.privileges:
                if p.operation == requested.operation:
                    declared.append(p)

        for p in declared:
            if p.subsumes(requested):
                return True
        return False

    def _target_in_user_intent(self, sink_call, user_intent: str) -> bool:
        """Check if the sink target appears in the user's original request."""
        if not user_intent:
            return False

        args = sink_call.arguments
        # Extract target from common sink argument patterns
        targets = []
        for key in ('to', 'recipient', 'url', 'endpoint', 'channel', 'path'):
            if key in args:
                targets.append(str(args[key]).lower())

        user_lower = user_intent.lower()
        for t in targets:
            # Check if target domain/address appears in user intent
            # e.g., "hr@corp.com" matches "send to HR"
            if '@' in t:
                domain = t.split('@')[-1]
                if domain in user_lower:
                    return True
            if t in user_lower:
                return True

        return False

    def _infer_sink_privilege(self, sink_call) -> SinkPrivilege:
        """Infer sink privilege from a tool call (for token issuance).

        Kept consistent with ``ElasticCapEngine._infer_sink_privilege``: the
        scope is resolved from the call's target argument (including the
        realistic MCP names such as ``channel`` / ``repo``), because the
        token binds the privilege string and the whitelist check compares
        the same value.
        """
        tool_name = sink_call.tool_name.lower()
        args = sink_call.arguments

        def _first(*keys):
            for k in keys:
                if k in args:
                    return args[k]
            return None

        if 'email' in tool_name or 'mail' in tool_name:
            to = _first('to', 'recipient', 'address')
            return SinkPrivilege(SinkType.SEND_EMAIL, str(to) if to is not None else '*')
        elif any(k in tool_name for k in ('http', 'url', 'fetch', 'post',
                                          'request', 'upload', 'webhook')):
            url = _first('url', 'endpoint', 'channel', 'channel_name', 'repo',
                         'repository', 'workspace', 'board', 'queue', 'topic',
                         'bucket')
            return SinkPrivilege(SinkType.SEND_HTTP, str(url) if url is not None else '*')
        elif 'write' in tool_name or 'save' in tool_name:
            path = _first('path', 'file', 'filename', 'output_path')
            return SinkPrivilege(SinkType.WRITE_FILE, str(path) if path is not None else '*')
        elif 'exec' in tool_name or 'shell' in tool_name:
            cmd = _first('command', 'cmd', 'script')
            return SinkPrivilege(SinkType.EXECUTE, str(cmd) if cmd is not None else '*')
        else:
            return SinkPrivilege(SinkType.DISPLAY)

    def _build_audit_prompt(self, sink_call,
                            dependency_chain: List[DataNode],
                            user_intent: str) -> str:
        """Build a structured prompt for the LLM auditor (Layer 2).

        KEY SECURITY: The prompt uses structured fields only.
        It does NOT pass free-text data through the LLM audit path
        without first passing Layer 1 checks.
        """
        tool_name = sink_call.tool_name
        args_summary = {
            k: v for k, v in sink_call.arguments.items()
            if k in ('to', 'recipient', 'url', 'endpoint', 'path', 'channel')
        }

        # Include the FULL body/content so Layer-2 can inspect for
        # semantic PII that Layer-1 regex patterns may have missed.
        body_content = ""
        for key in ('body', 'content', 'text', 'data', 'message'):
            if key in sink_call.arguments:
                body_content = str(sink_call.arguments[key])
                break

        chain_summary = []
        for node in dependency_chain[-5:]:  # Last 5 nodes only
            chain_summary.append(
                f"  - {node.label} (tool: {node.tool_name or 'unknown'}, "
                f"budget: {node.budget})"
            )

        prompt = f"""AUDIT TASK: Determine if a blocked sink operation should be allowed.

USER'S ORIGINAL REQUEST: {user_intent}

BLOCKED OPERATION:
  Tool: {tool_name}
  Target: {args_summary}
  Body: {body_content[:2000]}

DATA LINEAGE (last 5 nodes):
{chr(10).join(chain_summary)}

QUESTION: Has the data been sufficiently sanitized/aggregated such that
sending it to the target is safe? Consider:
1. Does the data contain individual-level PII or only aggregate statistics?
2. Is the target address consistent with the user's original request?
3. Would a reasonable security policy allow this operation?

Respond with exactly one word: GREEN, YELLOW, or RED."""
        return prompt

    @property
    def audit_log(self) -> List[AuditResult]:
        return list(self._audit_log)
