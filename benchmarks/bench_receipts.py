#!/usr/bin/env python3
"""Receipt issuance against a slow signer, as a key service is.

A :class:`~agentgov.receipts.ReceiptLog` issues receipts signed by an Ed25519
key wrapped to take ``--latency-ms`` per signature, the order of a round trip
to a KMS or a Vault. Issuance is measured with one caller and with
``--in-flight`` concurrent callers. A log that signs while holding its own
lock issues at most one receipt per signer round trip, however many callers
wait; one that signs outside it scales with the callers.

Usage::

    uv run python benchmarks/bench_receipts.py --latency-ms 50 --in-flight 16
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import ROOT, emit, machine

from agentgov.receipts import ActionReceipt, CheckpointPolicy, ReceiptLog
from agentgov.receipts.signing import Ed25519Signer


class SlowSigner:
    """An Ed25519 signer that takes ``latency`` seconds to answer, like a KMS."""

    def __init__(self, inner: Ed25519Signer, latency: float) -> None:
        self._inner = inner
        self._latency = latency
        self.calls = 0

    @property
    def alg(self) -> str:
        return self._inner.alg

    @property
    def key_id(self) -> str:
        return self._inner.key_id

    def public_key(self) -> Any:
        return self._inner.public_key()

    def sign(self, message: bytes) -> bytes:
        self.calls += 1
        time.sleep(self._latency)
        return self._inner.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self._inner.verify(message, signature)


def template() -> ActionReceipt:
    """A real receipt from the ARC1 vectors, unsigned and unplaced."""
    bundle = json.loads((ROOT / "vectors/arc1/valid/committed-refund.bundle.json").read_text())
    receipt = ActionReceipt.from_json(bundle["receipt"])
    anchors = dataclasses.replace(receipt.anchors, log=None)
    return dataclasses.replace(receipt, anchors=anchors, signature=None)


def issue(log: ReceiptLog, draft: ActionReceipt, count: int, in_flight: int) -> float:
    """Issue ``count`` receipts from ``in_flight`` threads; return the seconds taken."""
    per_thread = [
        count // in_flight + (1 if i < count % in_flight else 0) for i in range(in_flight)
    ]

    def run(n: int) -> None:
        for _ in range(n):
            log.issue(dataclasses.replace(draft, receipt_id=str(uuid.uuid4())))

    threads = [threading.Thread(target=run, args=(n,)) for n in per_thread]
    start = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return time.perf_counter() - start


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--latency-ms", type=float, default=50.0)
    parser.add_argument("--in-flight", type=int, default=16)
    parser.add_argument("--count", type=int, default=64)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    draft = template()
    results: dict[str, Any] = {}
    for label, in_flight in (("serial", 1), ("concurrent", args.in_flight)):
        signer = SlowSigner(Ed25519Signer.generate(), args.latency_ms / 1000)
        with tempfile.TemporaryDirectory() as tmp:
            log = ReceiptLog(
                "bench",
                signer,  # type: ignore[arg-type]
                path=Path(tmp) / "receipts.jsonl",
                policy=CheckpointPolicy(every_receipts=10**9, every_seconds=10**9),
            )
            try:
                count = args.count if in_flight > 1 else max(8, args.count // 4)
                seconds = issue(log, draft, count, in_flight)
            finally:
                log.close()
        results[f"{label}_per_s"] = round(count / seconds, 2)
    results["speedup"] = round(results["concurrent_per_s"] / results["serial_per_s"], 2)
    emit(
        {
            "bench": "receipts",
            **machine(),
            "signer_latency_ms": args.latency_ms,
            "in_flight": args.in_flight,
            **results,
        },
        args.out,
    )


if __name__ == "__main__":
    main()
