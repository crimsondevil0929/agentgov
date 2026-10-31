"""Reconciling a system of record's actions against the agent's receipts (1.1).

A cloud's audit trail, a cluster's audit log, a code host's audit log or a
clinical system's access log says what was done. Each action it saw is
either explained by a receipt, matched by an identifier both carry, or a
phantom: an action no receipt explains.
"""

from __future__ import annotations

import io
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import agentgov.reconciliation as reconciliation
from agentgov.cli import main
from agentgov.receipts import (
    ActionReceipt,
    Outcome,
    OutcomeStatus,
    ReceiptBundle,
    canonical_bytes,
)
from agentgov.reconciliation import (
    ActionRecord,
    Parser,
    UsageParseError,
    load_actions,
    parse_cloudtrail_json,
    parse_github_audit,
    parse_k8s_audit,
    parse_records,
    parsers,
    receipt_refs,
    reconcile_actions,
    register_parser,
)

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
ACTION = ReceiptBundle.loads(
    (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
).action_receipt
DELIVERY = ReceiptBundle.loads(
    (VECTORS / "delivery" / "valid" / "refund-delivered.bundle.json").read_bytes()
).delivery_receipt
AGENT = "arn:aws:sts::111122223333:assumed-role/sre-remediator/agent"


def _receipt(name: str, txid: str, *, committed: bool = True) -> ActionReceipt:
    status = OutcomeStatus.COMMITTED if committed else OutcomeStatus.REFUSED
    return replace(
        ACTION,
        receipt_id=f"00000000-0000-4000-8000-{name:0>12}",
        outcome=Outcome(status=status, substrate_txid=txid if committed else None),
        decision=replace(ACTION.decision, admitted=committed),
    )


def test_a_receipt_names_what_a_system_may_echo() -> None:
    refs = receipt_refs(ACTION)
    assert {
        ACTION.receipt_id,
        ACTION.intent.plan_hash,
        "stage:39fe5753-9447-57ea-b61e-eff46ef77bee",
        "39fe5753-9447-57ea-b61e-eff46ef77bee",
    } <= refs
    delivered = receipt_refs(DELIVERY)
    assert {"re_3Pq1VectorRefund", DELIVERY.request.idempotency_key} <= delivered
    assert receipt_refs(object()) == frozenset()


def test_cloudtrail_writes_are_actions_and_their_tokens_are_references() -> None:
    log = {
        "Records": [
            {
                "eventID": "e-1",
                "eventTime": "2026-10-30T10:00:00Z",
                "eventSource": "autoscaling.amazonaws.com",
                "eventName": "SetDesiredCapacity",
                "userIdentity": {"arn": AGENT},
                "requestParameters": {"clientRequestToken": "key-1"},
                "resources": [{"ARN": "arn:aws:autoscaling:asg/api"}],
            },
            {"eventID": "e-2", "eventTime": "2026-10-30T10:01:00Z", "readOnly": True},
        ]
    }
    (record,) = parse_cloudtrail_json(json.dumps(log))
    assert record.action == "autoscaling.amazonaws.com:SetDesiredCapacity"
    assert record.actor == AGENT and record.refs == ("key-1",)
    assert record.resource == "arn:aws:autoscaling:asg/api"
    with pytest.raises(UsageParseError, match="'Records' list"):
        parse_cloudtrail_json('{"events": []}')


def test_the_kubernetes_audit_log_counts_each_write_once() -> None:
    def event(verb: str, stage: str, annotations: dict[str, str]) -> str:
        return json.dumps(
            {
                "auditID": f"a-{verb}-{stage}",
                "stage": stage,
                "verb": verb,
                "user": {"username": "system:serviceaccount:ops:remediator"},
                "objectRef": {"resource": "deployments", "namespace": "prod", "name": "api"},
                "requestReceivedTimestamp": "2026-10-30T10:00:00.000000Z",
                "requestObject": {"metadata": {"annotations": annotations}},
            }
        )

    text = "\n".join(
        [
            event("patch", "RequestReceived", {"interlock.io/stage-id": "s-1"}),
            event("patch", "ResponseComplete", {"interlock.io/stage-id": "s-1", "x": "y"}),
            event("get", "ResponseComplete", {}),
            "",
        ]
    )
    (record,) = parse_k8s_audit(text)
    assert record.refs == ("s-1",) and record.resource == "deployments/prod/api"
    assert record.action == "patch"


def test_githubs_audit_log_names_the_commits_it_moved() -> None:
    events = [
        {
            "_document_id": "g-1",
            "@timestamp": 1793354400000,
            "actor": "agent-bot",
            "action": "git.push",
            "repo": "acme/api",
            "after": "c0ffee",
        }
    ]
    (record,) = parse_github_audit(json.dumps(events))
    assert record.refs == ("c0ffee",)
    assert record.timestamp == datetime(2026, 10, 30, 10, 0, tzinfo=UTC)


def test_any_other_log_is_read_with_a_field_map() -> None:
    access = (
        "event_id,ts,user,operation,object,correlation\n"
        "x1,2026-10-30T10:00:00Z,svc-medrec,order.create,MedicationRequest/88123,k-1 k-2\n"
    )
    columns = {
        "id": "event_id",
        "timestamp": "ts",
        "actor": "user",
        "action": "operation",
        "resource": "object",
        "refs": "correlation",
    }
    (record,) = parse_records(access, fields=columns)
    assert record.refs == ("k-1", "k-2") and record.action == "order.create"
    with pytest.raises(UsageParseError, match="no field 'who'"):
        parse_records(access, fields={"who": "user"})
    with pytest.raises(UsageParseError, match="no 'timestamp'"):
        parse_records('[{"id": 1}]')
    with pytest.raises(UsageParseError, match="unknown format"):
        parse_records("", fmt="xml")


def _record(name: str, actor: str, *refs: str) -> ActionRecord:
    return ActionRecord(
        record_id=name,
        timestamp=datetime(2026, 10, 30, tzinfo=UTC),
        actor=actor,
        action="update",
        resource="r",
        refs=refs,
        source="test",
    )


def test_every_action_a_governed_actor_took_must_be_explained() -> None:
    scaled = _receipt("1", "stage:s-1")
    refused = _receipt("2", "", committed=False)
    unseen = _receipt("3", "stage:s-3")
    records = [
        _record("by-stage", AGENT, "s-1"),
        _record("by-delivery", AGENT, DELIVERY.request.idempotency_key),
        _record("shadow", AGENT, "nothing-we-issued"),
        _record("human", "arn:aws:iam::111122223333:user/oncall"),
    ]
    report = reconcile_actions([scaled, refused, unseen, DELIVERY], records, actors=[AGENT])
    assert [(m.record.record_id, m.receipt_id) for m in report.matched] == [
        ("by-delivery", DELIVERY.receipt_id),
        ("by-stage", scaled.receipt_id),
    ]
    assert [r.record_id for r in report.phantom] == ["shadow"]
    assert report.unobserved == (unseen.receipt_id,), "a refused plan is not expected to be seen"
    assert report.ignored == 1 and not report.passed
    strict = reconcile_actions([scaled], [_record("human", "oncall")])
    assert len(strict.phantom) == 1, "with no actors given, every record must be explained"
    with pytest.raises(TypeError, match="not an ARC1 receipt"):
        reconcile_actions([object()], [])


def test_a_package_can_register_a_parser_of_its_own(monkeypatch: pytest.MonkeyPatch) -> None:
    def ehr(text: str, *, source: str = "ehr") -> tuple[ActionRecord, ...]:
        return tuple(_record(line, "svc", line) for line in text.split())

    monkeypatch.setattr(reconciliation, "_PARSERS", dict(reconciliation._PARSERS))
    custom = Parser("ehr-access", "actions", ehr)
    register_parser(custom)
    register_parser(custom)  # the same one again is no conflict
    assert parsers("actions")["ehr-access"] is custom
    assert "ehr-access" not in parsers("usage")
    with pytest.raises(ValueError, match="is registered"):
        register_parser(Parser("ehr-access", "actions", ehr))
    with pytest.raises(ValueError, match="'usage' or 'actions'"):
        register_parser(Parser("odd", "events", ehr))


def test_installed_parsers_load_from_their_entry_points(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = Parser("erp-changes", "actions", parse_records)

    class Point:
        name = "erp-changes"

        def __init__(self, loaded: Any) -> None:
            self._loaded = loaded

        def load(self) -> Any:
            return self._loaded

    import importlib.metadata

    monkeypatch.setattr(reconciliation, "_PARSERS", dict(reconciliation._PARSERS))
    monkeypatch.setattr(reconciliation, "_PLUGINS_LOADED", False)
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda group: [Point(plugin)])
    assert parsers()["erp-changes"] is plugin
    monkeypatch.setattr(reconciliation, "_PLUGINS_LOADED", False)
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda group: [Point("nope")])
    with pytest.raises(UsageParseError, match="not a Parser"):
        parsers()


def test_reconcile_actions_from_the_terminal(tmp_path: Path) -> None:
    receipts = tmp_path / "receipts.jsonl"
    scaled = _receipt("1", "stage:s-1")
    receipts.write_bytes(canonical_bytes(scaled.to_json()) + b"\n")
    export = tmp_path / "audit.jsonl"
    export.write_text(
        json.dumps({"id": "x", "timestamp": "2026-10-30T10:00:00Z", "actor": AGENT, "refs": "s-1"})
        + "\n"
    )
    out = io.StringIO()
    assert main(["reconcile-actions", str(receipts), str(export), "--actor", AGENT], out=out) == 0
    assert "AUDIT PASSED" in out.getvalue()
    export.write_text(
        json.dumps({"who": AGENT, "when": "2026-10-30T10:00:00Z", "token": "elsewhere"}) + "\n"
    )
    out = io.StringIO()
    args = [
        "reconcile-actions",
        str(receipts),
        str(export),
        "--field",
        "actor=who",
        "--field",
        "timestamp=when",
        "--field",
        "refs=token",
    ]
    assert main(args, out=out) == 1
    assert "1 phantom action(s)" in out.getvalue()
    out = io.StringIO()
    assert main([*args[:3], "--field", "actor"], out=out) == 1
    assert "NAME=COLUMN" in out.getvalue()
    receipts.write_text("{}\n")
    export.write_text("[]")
    out = io.StringIO()
    assert main(["reconcile-actions", str(receipts), str(export)], out=out) == 1
    assert "line 1" in out.getvalue()
    with pytest.raises(UsageParseError, match="unknown format"):
        load_actions(export, fmt="cloudtrail")


def test_malformed_exports_say_where(tmp_path: Path) -> None:
    with pytest.raises(UsageParseError, match="line 2: invalid JSON"):
        parse_records('{"timestamp": "2026-10-30T00:00:00Z"}\n{oops\n', fmt="json")
    with pytest.raises(UsageParseError, match="record 0: expected an object"):
        parse_cloudtrail_json('{"Records": [1]}')
    with pytest.raises(UsageParseError, match="event 0: expected an object"):
        parse_k8s_audit("[1]")
    with pytest.raises(UsageParseError, match="event 0: expected an object"):
        parse_github_audit('"x"')
    with pytest.raises(UsageParseError, match="row 0: expected an object"):
        parse_records("[1]", fmt="json")
    with pytest.raises(UsageParseError, match="invalid JSON"):
        parse_cloudtrail_json("{")
    with pytest.raises(UsageParseError, match="cannot read"):
        load_actions(tmp_path / "missing.json")
    (record,) = parse_cloudtrail_json(
        '[{"eventTime": "2026-10-30T00:00:00Z", "userIdentity": "not an object"}]'
    )
    assert record.actor == "" and record.record_id == "cloudtrail-json#0"


def test_a_long_list_of_phantoms_is_cut_in_the_report() -> None:
    from agentgov.reconciliation import format_action_report

    report = reconcile_actions([], [_record(f"r{n}", AGENT, f"x{n}") for n in range(12)])
    text = format_action_report(report, export="audit.jsonl")
    assert "... and 2 more" in text and "system of record  audit.jsonl" in text
