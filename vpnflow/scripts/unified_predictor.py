#!/usr/bin/env python3
"""Production-oriented unified predictor for one offline PCAP file."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = "1.0"
MODEL_ORDER = ("trojan", "shadowsocks")
VALID_MODEL_STATES = {"shadow", "promoted", "disabled"}
VALID_MODES = {"shadow", "enforce"}


class PredictorError(RuntimeError):
    """Fatal CLI or input error."""


class RowScoreError(ValueError):
    """A single row cannot be safely scored."""


@dataclass
class RuntimeModel:
    name: str
    label: str
    version: str
    status: str
    threshold: float
    features: list[str]
    applicability: list[dict[str, Any]]
    scorer: Callable[[list[float]], float] | None = None
    error: str | None = None
    counters: Counter = field(default_factory=Counter)

    @property
    def available(self) -> bool:
        return self.scorer is not None and self.error is None and self.status != "disabled"

    def validate_header(self, header: set[str]) -> None:
        required = set(self.features)
        required.update(str(gate.get("column", "")) for gate in self.applicability)
        missing = sorted(column for column in required if column and column not in header)
        if missing:
            self.error = "feature_schema_mismatch: missing " + ",".join(missing)
            self.scorer = None

    def is_applicable(self, row: dict[str, str]) -> bool:
        for gate in self.applicability:
            column = str(gate["column"])
            try:
                actual = _finite_float(row.get(column), column)
                expected = float(gate["value"])
            except (KeyError, RowScoreError):
                return False
            operation = gate.get("op")
            if operation == "eq" and actual != expected:
                return False
            if operation == "gte" and actual < expected:
                return False
            if operation == "gt" and actual <= expected:
                return False
            if operation not in {"eq", "gte", "gt"}:
                return False
        return True

    def score(self, row: dict[str, str]) -> float:
        if not self.available or self.scorer is None:
            raise RowScoreError(self.error or "model_unavailable")
        values = [_finite_float(row.get(column), column) for column in self.features]
        probability = float(self.scorer(values))
        if not math.isfinite(probability) or probability < 0.0 or probability > 1.0:
            raise RowScoreError("invalid_model_probability")
        return probability


def _finite_float(value: Any, column: str) -> float:
    if value is None or value == "":
        raise RowScoreError(f"missing_feature:{column}")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise RowScoreError(f"invalid_feature:{column}") from exc
    if not math.isfinite(number):
        raise RowScoreError(f"nonfinite_feature:{column}")
    return number


class XGBoostScorer:
    def __init__(self, booster: Any, features: list[str], xgb_module: Any):
        self.booster = booster
        self.features = features
        self.xgb = xgb_module

    def __call__(self, values: list[float]) -> float:
        return self.predict_many([values])[0]

    def predict_many(self, values: list[list[float]]) -> list[float]:
        matrix = self.xgb.DMatrix(values, feature_names=self.features)
        return [float(value) for value in self.booster.predict(matrix)]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_models(model_dir: Path) -> tuple[dict[str, RuntimeModel], dict[str, Any]]:
    manifest_path = model_dir / "manifest.json"
    if not manifest_path.is_file():
        return {}, {"loaded": False, "error": "manifest_not_found", "path": str(manifest_path)}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, {"loaded": False, "error": f"manifest_invalid:{exc}", "path": str(manifest_path)}
    if manifest.get("schema_version") != SCHEMA_VERSION or not isinstance(manifest.get("models"), dict):
        return {}, {"loaded": False, "error": "manifest_schema_mismatch", "path": str(manifest_path)}

    try:
        import xgboost as xgb
    except Exception as exc:  # pragma: no cover - environment dependent
        xgb = None
        import_error = f"xgboost_unavailable:{exc}"
    else:
        import_error = None

    loaded: dict[str, RuntimeModel] = {}
    resolved_model_dir = model_dir.resolve()
    for name in MODEL_ORDER:
        definition = manifest["models"].get(name)
        if not isinstance(definition, dict):
            continue
        runtime = RuntimeModel(name, name, "unknown", "disabled", 1.0, [], [])
        try:
            status = str(definition["status"])
            threshold = float(definition["threshold"])
            features = [str(value) for value in definition["features"]]
            applicability = list(definition["applicability"])
            if status not in VALID_MODEL_STATES:
                raise ValueError("invalid status")
            if not 0.0 <= threshold <= 1.0:
                raise ValueError("threshold outside [0,1]")
            if not features or len(features) != len(set(features)):
                raise ValueError("features must be non-empty and unique")
            if str(definition.get("label", name)) != name:
                raise ValueError("model label mismatch")
            for gate in applicability:
                if (
                    not isinstance(gate, dict)
                    or not isinstance(gate.get("column"), str)
                    or gate.get("op") not in {"eq", "gte", "gt"}
                    or not isinstance(gate.get("value"), (int, float))
                ):
                    raise ValueError("invalid applicability gate")
            runtime = RuntimeModel(
                name=name,
                label=str(definition.get("label", name)),
                version=str(definition["version"]),
                status=status,
                threshold=threshold,
                features=features,
                applicability=applicability,
            )
            model_path = (model_dir / str(definition["file"])).resolve()
            if model_path.parent != resolved_model_dir:
                raise ValueError("model path must stay inside model-dir")
            expected_hash = str(definition["sha256"]).lower()
            if len(expected_hash) != 64 or any(character not in "0123456789abcdef" for character in expected_hash):
                raise ValueError("invalid model sha256")
            if not model_path.is_file():
                raise ValueError("model_file_not_found")
            if _sha256(model_path).lower() != expected_hash:
                raise ValueError("model_hash_mismatch")
            if import_error:
                raise ValueError(import_error)
            booster = xgb.Booster()
            booster.load_model(model_path)
            if booster.feature_names is not None and booster.feature_names != features:
                raise ValueError("model feature order mismatch")
            runtime.scorer = XGBoostScorer(booster, features, xgb)
        except Exception as exc:
            # A broken model fails closed without disabling standard protocol rules.
            runtime.error = str(exc)
            runtime.scorer = None
        loaded[name] = runtime
    return loaded, {
        "loaded": True,
        "path": str(manifest_path),
        "predictor_version": manifest.get("predictor_version", "unknown"),
    }


def read_features(path: Path) -> tuple[list[dict[str, str]], set[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise PredictorError("feature CSV has no header")
        return list(reader), set(reader.fieldnames)


def read_protocol_results(path: Path) -> list[dict[str, Any]]:
    results = []
    if not path.exists():
        return results
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PredictorError(f"invalid protocol JSONL at line {line_number}: {exc}") from exc
            if not isinstance(item.get("flows", []), list):
                raise PredictorError(f"invalid protocol JSONL flows at line {line_number}")
            results.append(item)
    return results


def _protocol_rank(item: dict[str, Any]) -> tuple[int, float]:
    return (1 if item.get("verdict") == "confirmed" else 0, float(item.get("confidence", 0.0)))


def protocol_flow_map(results: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    mapping: dict[tuple[str, str], dict[str, Any]] = {}
    for result in results:
        source = str(result.get("source_file", ""))
        for flow_key in result.get("flows", []):
            key = (source, str(flow_key))
            if key not in mapping or _protocol_rank(result) > _protocol_rank(mapping[key]):
                mapping[key] = result
    return mapping


def _standard_from_row(row: dict[str, str], mapped: dict[str, Any] | None) -> dict[str, Any] | None:
    if mapped is not None:
        return mapped
    protocol = row.get("standard_protocol", "")
    verdict = row.get("standard_protocol_verdict", "")
    if not protocol or verdict not in {"confirmed", "suspected"}:
        return None
    return {
        "protocol": protocol,
        "verdict": verdict,
        "confidence": 1.0 if verdict == "confirmed" else 0.5,
        "session_id": row.get("protocol_session_id", ""),
    }


def evaluate_models(
    rows: list[dict[str, str] | None],
    models: dict[str, RuntimeModel],
) -> list[dict[str, tuple[float | None, str | None]]]:
    evaluations: list[dict[str, tuple[float | None, str | None]]] = [dict() for _ in rows]
    for name in MODEL_ORDER:
        runtime = models.get(name)
        if runtime is None:
            for result in evaluations:
                result[name] = (None, "model_unavailable")
            continue
        if not runtime.available or runtime.scorer is None:
            runtime.counters["unavailable"] += len(rows)
            for result in evaluations:
                result[name] = (None, "model_unavailable")
            continue

        batch_indexes: list[int] = []
        batch_values: list[list[float]] = []
        for index, row in enumerate(rows):
            if row is None or not runtime.is_applicable(row):
                runtime.counters["skipped"] += 1
                evaluations[index][name] = (None, "not_applicable")
                continue
            runtime.counters["applicable"] += 1
            try:
                values = [_finite_float(row.get(column), column) for column in runtime.features]
            except RowScoreError as exc:
                runtime.counters["row_errors"] += 1
                evaluations[index][name] = (None, f"score_error:{exc}")
                continue
            batch_indexes.append(index)
            batch_values.append(values)

        if not batch_indexes:
            continue
        try:
            scorer = runtime.scorer
            if hasattr(scorer, "predict_many"):
                probabilities = scorer.predict_many(batch_values)
            else:
                probabilities = [scorer(values) for values in batch_values]
            if len(probabilities) != len(batch_indexes):
                raise RowScoreError("invalid_model_output_length")
        except Exception as exc:
            runtime.counters["row_errors"] += len(batch_indexes)
            for index in batch_indexes:
                evaluations[index][name] = (None, f"score_error:{exc}")
            continue
        for index, probability_value in zip(batch_indexes, probabilities):
            probability = float(probability_value)
            if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
                runtime.counters["row_errors"] += 1
                evaluations[index][name] = (None, "score_error:invalid_model_probability")
                continue
            runtime.counters["scored"] += 1
            if probability >= runtime.threshold:
                runtime.counters["above_threshold"] += 1
            evaluations[index][name] = (probability, None)
    return evaluations


def decide_flow(
    row: dict[str, str] | None,
    standard: dict[str, Any] | None,
    models: dict[str, RuntimeModel],
    mode: str,
    source: str,
    flow_key: str,
    evaluations: dict[str, tuple[float | None, str | None]] | None = None,
) -> dict[str, Any]:
    if mode not in VALID_MODES:
        raise PredictorError(f"invalid mode: {mode}")
    scores: dict[str, float | None] = {}
    versions: dict[str, str] = {}
    reasons: list[str] = []
    above: list[RuntimeModel] = []
    promoted_above: list[RuntimeModel] = []

    if evaluations is None:
        evaluations = evaluate_models([row], models)[0]
    for name in MODEL_ORDER:
        model = models.get(name)
        scores[name] = None
        if model is None:
            reasons.append(f"{name}_model_unavailable")
            continue
        versions[name] = model.version
        score, reason = evaluations.get(name, (None, "model_unavailable"))
        if reason is not None:
            reasons.append(f"{name}_{reason}")
            continue
        if score is None:
            reasons.append(f"{name}_score_error:missing_score")
            continue
        scores[name] = round(score, 10)
        if score >= model.threshold:
            above.append(model)
            if model.status == "promoted":
                promoted_above.append(model)

    standard_protocol = str(standard.get("protocol", "")) if standard else ""
    standard_verdict = str(standard.get("verdict", "")) if standard else ""
    session_id = str(standard.get("session_id", "")) if standard else ""
    if not session_id and row:
        session_id = row.get("protocol_session_id", "")

    final_label = "unknown"
    verdict = "unknown"
    confidence = 0.0
    decision_source = "fallback"
    if standard and standard_verdict == "confirmed":
        final_label = standard_protocol
        verdict = "confirmed"
        confidence = float(standard.get("confidence", 1.0))
        decision_source = "standard_rule"
        reasons.append("standard_confirmed")
        if above:
            reasons.append("standard_ml_candidate_conflict")
    else:
        if standard and standard_verdict == "suspected":
            reasons.append("standard_suspected")
        decision_candidates = promoted_above if mode == "enforce" else []
        if len(decision_candidates) > 1:
            reasons.append("model_conflict")
        elif len(decision_candidates) == 1:
            selected = decision_candidates[0]
            final_label = selected.label
            verdict = "predicted"
            confidence = float(scores[selected.name] or 0.0)
            decision_source = f"{selected.name}_xgb"
            reasons.append(f"{selected.name}_predicted")
        elif above:
            if len(above) > 1:
                reasons.append("model_conflict")
            else:
                reasons.append(f"shadow_{above[0].name}_candidate")
            if mode == "enforce" and not promoted_above:
                reasons.append("candidate_model_not_promoted")
        else:
            reasons.append("no_model_above_threshold")

    trojan_applicable = 0
    if row is not None:
        try:
            trojan_applicable = int(float(row.get("trojan_applicable", "0") or 0))
        except ValueError:
            trojan_applicable = 0
    return {
        "schema_version": SCHEMA_VERSION,
        "pcap": source,
        "flow_key": flow_key,
        "protocol_session_id": session_id,
        "final_label": final_label,
        "verdict": verdict,
        "confidence": round(confidence, 10),
        "decision_source": decision_source,
        "standard_protocol": standard_protocol,
        "standard_verdict": standard_verdict,
        "trojan_applicable": trojan_applicable,
        "model_scores": scores,
        "model_versions": versions,
        "reason_codes": sorted(set(reasons)),
    }


def build_predictions(
    rows: list[dict[str, str]],
    protocol_results: list[dict[str, Any]],
    models: dict[str, RuntimeModel],
    mode: str,
    default_source: str,
) -> list[dict[str, Any]]:
    mapping = protocol_flow_map(protocol_results)
    entries: list[tuple[dict[str, str] | None, dict[str, Any] | None, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        source = row.get("source_file", "") or default_source
        flow_key = row.get("flow_key", "")
        key = (source, flow_key)
        standard = _standard_from_row(row, mapping.get(key))
        entries.append((row, standard, source, flow_key))
        seen.add(key)

    # UDP/GRE standard protocols do not have TCP ML rows, but must still be emitted.
    for key in sorted(mapping):
        if key in seen:
            continue
        source, flow_key = key
        entries.append((None, mapping[key], source or default_source, flow_key))

    evaluations = evaluate_models([entry[0] for entry in entries], models)
    return [
        decide_flow(row, standard, models, mode, source, flow_key, evaluation)
        for (row, standard, source, flow_key), evaluation in zip(entries, evaluations)
    ]


def build_summary(
    input_pcap: Path,
    mode: str,
    predictions: list[dict[str, Any]],
    rows: list[dict[str, str]],
    protocol_results: list[dict[str, Any]],
    models: dict[str, RuntimeModel],
    manifest_status: dict[str, Any],
    elapsed_ms: int,
    extractor_ms: int,
) -> dict[str, Any]:
    final_labels = Counter(item["final_label"] for item in predictions)
    verdicts = Counter(item["verdict"] for item in predictions)
    session_protocols = Counter(
        str(item.get("protocol", "unknown")) for item in protocol_results
    )
    session_verdicts = Counter(
        str(item.get("verdict", "unknown")) for item in protocol_results
    )
    model_status = {}
    for name in MODEL_ORDER:
        model = models.get(name)
        if model is None:
            model_status[name] = {
                "available": False,
                "manifest_status": "missing",
                "error": "model_definition_missing",
                "applicable": 0,
                "skipped": len(predictions),
                "scored": 0,
                "above_threshold": 0,
                "row_errors": 0,
            }
            continue
        model_status[name] = {
            "available": model.available,
            "manifest_status": model.status,
            "version": model.version,
            "threshold": model.threshold,
            "error": model.error,
            "applicable": model.counters["applicable"],
            "skipped": model.counters["skipped"],
            "scored": model.counters["scored"],
            "above_threshold": model.counters["above_threshold"],
            "row_errors": model.counters["row_errors"],
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "input_pcap": str(input_pcap),
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": elapsed_ms,
        "extractor_duration_ms": extractor_ms,
        "counts": {
            "feature_flows": len(rows),
            "total_results": len(predictions),
            "protocol_only_flows": max(0, len(predictions) - len(rows)),
            "final_labels": dict(sorted(final_labels.items())),
            "verdicts": dict(sorted(verdicts.items())),
            "shadow_candidates": sum(
                any(code.startswith("shadow_") for code in item["reason_codes"])
                for item in predictions
            ),
            "model_conflicts": sum(
                "model_conflict" in item["reason_codes"] for item in predictions
            ),
            "standard_ml_candidate_conflicts": sum(
                "standard_ml_candidate_conflict" in item["reason_codes"]
                for item in predictions
            ),
        },
        "protocol_sessions": {
            "total": len(protocol_results),
            "by_protocol": dict(sorted(session_protocols.items())),
            "by_verdict": dict(sorted(session_verdicts.items())),
        },
        "manifest": manifest_status,
        "models": model_status,
    }


def atomic_write_jsonl(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            for item in items:
                handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, item: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(item, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def log_event(event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=sys.stderr)


def run_extractor(vpnflow_bin: Path, pcap: Path, work_dir: Path) -> tuple[Path, Path, int]:
    features_path = work_dir / "features.csv"
    protocols_path = work_dir / "protocols.jsonl"
    command = [
        str(vpnflow_bin),
        "--pcap", str(pcap),
        "--output", str(features_path),
        "--protocol-output", str(protocols_path),
        "--inference",
    ]
    started = time.perf_counter()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise PredictorError(f"cannot start vpnflow extractor: {exc}") from exc
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise PredictorError(f"vpnflow extractor failed ({completed.returncode}): {detail}")
    if completed.stderr.strip():
        log_event("extractor_warning", message=completed.stderr.strip())
    return features_path, protocols_path, elapsed_ms


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="vpnflow unified final predictor")
    parser.add_argument("--pcap", required=True, help="single input .pcap or .pcapng file")
    parser.add_argument("--vpnflow-bin", default="out/vpnflow", help="Go vpnflow executable")
    parser.add_argument("--model-dir", default="models", help="directory containing manifest.json")
    parser.add_argument("--mode", choices=sorted(VALID_MODES), default="shadow")
    parser.add_argument("--flow-output", required=True, help="per-flow JSONL output")
    parser.add_argument("--summary-output", required=True, help="PCAP summary JSON output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    started = time.perf_counter()
    pcap = Path(args.pcap).resolve()
    vpnflow_bin = Path(args.vpnflow_bin).resolve()
    model_dir = Path(args.model_dir).resolve()
    flow_output = Path(args.flow_output).resolve()
    summary_output = Path(args.summary_output).resolve()
    if not pcap.is_file() or pcap.suffix.lower() not in {".pcap", ".pcapng"}:
        raise PredictorError(f"input must be one existing .pcap/.pcapng file: {pcap}")
    if flow_output == summary_output:
        raise PredictorError("flow-output and summary-output must be different files")

    log_event("prediction_started", pcap=str(pcap), mode=args.mode)
    with tempfile.TemporaryDirectory(prefix="vpnflow-predict-") as temporary:
        features_path, protocols_path, extractor_ms = run_extractor(
            vpnflow_bin, pcap, Path(temporary)
        )
        rows, header = read_features(features_path)
        protocols = read_protocol_results(protocols_path)
        models, manifest_status = load_models(model_dir)
        for model in models.values():
            model.validate_header(header)
        predictions = build_predictions(rows, protocols, models, args.mode, pcap.name)
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        summary = build_summary(
            pcap, args.mode, predictions, rows, protocols, models,
            manifest_status, elapsed_ms, extractor_ms,
        )
        atomic_write_jsonl(flow_output, predictions)
        atomic_write_json(summary_output, summary)
    log_event(
        "prediction_completed",
        flows=len(predictions),
        flow_output=str(flow_output),
        summary_output=str(summary_output),
        duration_ms=summary["duration_ms"],
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PredictorError as exc:
        log_event("prediction_failed", error=str(exc))
        raise SystemExit(2)
