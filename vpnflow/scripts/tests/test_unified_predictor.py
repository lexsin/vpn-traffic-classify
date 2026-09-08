from __future__ import annotations

import math
import json
import tempfile
import unittest
from pathlib import Path

from scripts.unified_predictor import (
    RuntimeModel,
    build_predictions,
    decide_flow,
    load_models,
)


def model(
    name: str,
    score: float,
    *,
    status: str = "promoted",
    threshold: float = 0.8,
    gates: list[dict] | None = None,
    features: list[str] | None = None,
) -> RuntimeModel:
    return RuntimeModel(
        name=name,
        label=name,
        version="test-v1",
        status=status,
        threshold=threshold,
        features=features or ["feature"],
        applicability=gates or [],
        scorer=lambda _: score,
    )


class UnifiedDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.row = {
            "source_file": "sample.pcap",
            "flow_key": "tcp|1.1.1.1:1|2.2.2.2:2",
            "feature": "1",
            "trojan_applicable": "1",
            "tcp_handshake_complete": "1",
        }

    def test_confirmed_standard_always_wins(self) -> None:
        trojan = model("trojan", 0.99)
        result = decide_flow(
            self.row,
            {"protocol": "openvpn", "verdict": "confirmed", "confidence": 0.96, "session_id": "s1"},
            {"trojan": trojan},
            "enforce",
            "sample.pcap",
            self.row["flow_key"],
        )
        self.assertEqual(result["final_label"], "openvpn")
        self.assertEqual(result["decision_source"], "standard_rule")
        self.assertIn("standard_ml_candidate_conflict", result["reason_codes"])

    def test_shadow_mode_never_enforces_ml(self) -> None:
        result = decide_flow(
            self.row, None, {"trojan": model("trojan", 0.99)}, "shadow",
            "sample.pcap", self.row["flow_key"],
        )
        self.assertEqual(result["final_label"], "unknown")
        self.assertEqual(result["verdict"], "unknown")
        self.assertIn("shadow_trojan_candidate", result["reason_codes"])

    def test_enforce_uses_only_promoted_model(self) -> None:
        shadow = model("trojan", 0.99, status="shadow")
        result = decide_flow(
            self.row, None, {"trojan": shadow}, "enforce",
            "sample.pcap", self.row["flow_key"],
        )
        self.assertEqual(result["final_label"], "unknown")
        self.assertIn("candidate_model_not_promoted", result["reason_codes"])

    def test_trojan_without_post_tls_is_not_scored(self) -> None:
        trojan = model(
            "trojan", 0.99,
            gates=[{"column": "trojan_applicable", "op": "eq", "value": 1}],
        )
        row = dict(self.row, trojan_applicable="0")
        result = decide_flow(row, None, {"trojan": trojan}, "enforce", "sample.pcap", row["flow_key"])
        self.assertIsNone(result["model_scores"]["trojan"])
        self.assertEqual(result["final_label"], "unknown")
        self.assertIn("trojan_not_applicable", result["reason_codes"])

    def test_shadowsocks_requires_complete_handshake(self) -> None:
        shadowsocks = model(
            "shadowsocks", 0.99,
            gates=[{"column": "tcp_handshake_complete", "op": "eq", "value": 1}],
        )
        row = dict(self.row, tcp_handshake_complete="0")
        result = decide_flow(
            row, None, {"shadowsocks": shadowsocks}, "enforce",
            "sample.pcap", row["flow_key"],
        )
        self.assertEqual(result["final_label"], "unknown")
        self.assertIn("shadowsocks_not_applicable", result["reason_codes"])

    def test_two_promoted_models_conflict(self) -> None:
        models = {
            "trojan": model("trojan", 0.9),
            "shadowsocks": model("shadowsocks", 0.95),
        }
        result = decide_flow(self.row, None, models, "enforce", "sample.pcap", self.row["flow_key"])
        self.assertEqual(result["final_label"], "unknown")
        self.assertIn("model_conflict", result["reason_codes"])

    def test_threshold_is_inclusive(self) -> None:
        result = decide_flow(
            self.row, None, {"trojan": model("trojan", 0.8, threshold=0.8)}, "enforce",
            "sample.pcap", self.row["flow_key"],
        )
        self.assertEqual(result["final_label"], "trojan")

    def test_nonfinite_feature_fails_closed(self) -> None:
        row = dict(self.row, feature=str(math.nan))
        result = decide_flow(
            row, None, {"trojan": model("trojan", 0.99)}, "enforce",
            "sample.pcap", row["flow_key"],
        )
        self.assertEqual(result["final_label"], "unknown")
        self.assertTrue(any(code.startswith("trojan_score_error:nonfinite_feature") for code in result["reason_codes"]))

    def test_suspected_standard_does_not_claim_final_label(self) -> None:
        result = decide_flow(
            self.row,
            {"protocol": "openvpn", "verdict": "suspected", "confidence": 0.6},
            {}, "enforce", "sample.pcap", self.row["flow_key"],
        )
        self.assertEqual(result["final_label"], "unknown")
        self.assertEqual(result["standard_protocol"], "openvpn")
        self.assertIn("standard_suspected", result["reason_codes"])

    def test_protocol_only_flow_is_emitted(self) -> None:
        protocol = [{
            "source_file": "sample.pcap",
            "session_id": "wg-1",
            "protocol": "wireguard",
            "verdict": "confirmed",
            "confidence": 1.0,
            "flows": ["udp|1.1.1.1:1|2.2.2.2:2"],
        }]
        results = build_predictions([], protocol, {}, "shadow", "sample.pcap")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["final_label"], "wireguard")
        self.assertEqual(results[0]["protocol_session_id"], "wg-1")

    def test_empty_input_is_valid(self) -> None:
        self.assertEqual(build_predictions([], [], {}, "shadow", "empty.pcap"), [])

    def test_header_mismatch_disables_model(self) -> None:
        runtime = model("trojan", 0.9, features=["required"])
        runtime.validate_header({"another"})
        self.assertFalse(runtime.available)
        self.assertIn("feature_schema_mismatch", runtime.error or "")

    def test_missing_model_artifact_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            model_dir = Path(temporary)
            manifest = {
                "schema_version": "1.0",
                "models": {
                    "trojan": {
                        "label": "trojan",
                        "version": "test-v1",
                        "status": "promoted",
                        "threshold": 0.9,
                        "features": ["feature"],
                        "applicability": [],
                        "file": "missing.xgb.json",
                        "sha256": "0" * 64,
                    }
                },
            }
            (model_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            models, status = load_models(model_dir)
        self.assertTrue(status["loaded"])
        self.assertFalse(models["trojan"].available)
        self.assertIn("model_file_not_found", models["trojan"].error or "")

    def test_build_predictions_batches_model_scoring(self) -> None:
        class BatchScorer:
            def __init__(self) -> None:
                self.calls = 0

            def __call__(self, values: list[float]) -> float:
                raise AssertionError("single-row scoring should not be used")

            def predict_many(self, values: list[list[float]]) -> list[float]:
                self.calls += 1
                return [0.9 for _ in values]

        scorer = BatchScorer()
        runtime = model("shadowsocks", 0.9)
        runtime.scorer = scorer
        rows = [
            dict(self.row, flow_key="flow-1"),
            dict(self.row, flow_key="flow-2"),
        ]
        results = build_predictions(rows, [], {"shadowsocks": runtime}, "enforce", "sample.pcap")
        self.assertEqual(scorer.calls, 1)
        self.assertEqual([item["final_label"] for item in results], ["shadowsocks", "shadowsocks"])


if __name__ == "__main__":
    unittest.main()
