#!/usr/bin/env python3
"""Train, validate, and export versioned XGBoost artifacts for unified inference."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import sklearn
import xgboost as xgb

try:
    from .model_spec import MODEL_SPECS
except ImportError:
    from model_spec import MODEL_SPECS

SCHEMA_VERSION = "1.0"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_model(y: np.ndarray) -> xgb.XGBClassifier:
    positives = int((y == 1).sum())
    negatives = int((y == 0).sum())
    if positives == 0 or negatives == 0:
        raise ValueError("training data must contain both positive and negative rows")
    return xgb.XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=negatives / positives,
        eval_metric="auc",
        n_jobs=4,
        random_state=42,
        verbosity=0,
    )


def apply_gates(frame: pd.DataFrame, gates: list[dict[str, Any]]) -> pd.DataFrame:
    keep = pd.Series(True, index=frame.index)
    for gate in gates:
        column = gate["column"]
        values = pd.to_numeric(frame[column], errors="coerce")
        expected = float(gate["value"])
        if gate["op"] == "eq":
            keep &= values == expected
        elif gate["op"] == "gte":
            keep &= values >= expected
        elif gate["op"] == "gt":
            keep &= values > expected
        else:
            raise ValueError(f"unsupported gate operation: {gate['op']}")
    return frame.loc[keep].copy().reset_index(drop=True)


def metrics(y: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict[str, Any]:
    prediction = probabilities >= threshold
    tp = int((prediction & (y == 1)).sum())
    fp = int((prediction & (y == 0)).sum())
    tn = int(((~prediction) & (y == 0)).sum())
    fn = int(((~prediction) & (y == 1)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    return {
        "rows": int(len(y)),
        "positive_rows": int((y == 1).sum()),
        "negative_rows": int((y == 0).sum()),
        "predicted_positive": tp + fp,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def leave_one_source_out(
    frame: pd.DataFrame, features: list[str]
) -> tuple[np.ndarray, np.ndarray, list[dict[str, Any]]]:
    probabilities = np.full(len(frame), np.nan, dtype=float)
    valid = np.zeros(len(frame), dtype=bool)
    details = []
    for source in sorted(frame["source_file"].astype(str).unique()):
        validation = frame["source_file"].astype(str) == source
        training = ~validation
        y_train = frame.loc[training, "y"].to_numpy(dtype=int)
        detail: dict[str, Any] = {
            "source": source,
            "rows": int(validation.sum()),
            "positive_rows": int(frame.loc[validation, "y"].sum()),
        }
        if len(np.unique(y_train)) < 2:
            detail["valid"] = False
            detail["error"] = "training_fold_has_single_class"
            details.append(detail)
            continue
        model = make_model(y_train)
        model.fit(frame.loc[training, features], y_train)
        fold_probabilities = model.predict_proba(frame.loc[validation, features])[:, 1]
        mask = validation.to_numpy()
        probabilities[mask] = fold_probabilities
        valid[mask] = True
        detail["valid"] = True
        detail["mean_probability"] = float(fold_probabilities.mean())
        details.append(detail)
    return probabilities, valid, details


def select_threshold(
    y: np.ndarray, probabilities: np.ndarray, target_precision: float
) -> tuple[float, dict[str, Any], bool]:
    candidates = sorted({float(value) for value in probabilities if math.isfinite(float(value))})
    qualifying: list[tuple[float, float, float, dict[str, Any]]] = []
    for threshold in candidates:
        result = metrics(y, probabilities, threshold)
        if result["predicted_positive"] > 0 and result["precision"] > target_precision:
            qualifying.append((result["recall"], result["precision"], -threshold, result))
    if not qualifying:
        threshold = 1.0
        return threshold, metrics(y, probabilities, threshold), False
    _, _, negative_threshold, result = max(qualifying)
    return -negative_threshold, result, True


def validate_frame(frame: pd.DataFrame, features: list[str], gates: list[dict[str, Any]]) -> None:
    required = set(features) | {"label", "source_file"}
    required.update(gate["column"] for gate in gates)
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError("training CSV missing columns: " + ",".join(missing))
    values = frame[features].apply(pd.to_numeric, errors="coerce")
    if not np.isfinite(values.to_numpy(dtype=float)).all():
        raise ValueError("training CSV contains missing/non-finite model features")


def train_one(
    name: str,
    raw: pd.DataFrame,
    output_dir: Path,
    model_version: str,
    target_precision: float,
) -> dict[str, Any]:
    spec = MODEL_SPECS[name]
    features = list(spec["features"])
    gates = list(spec["applicability"])
    validate_frame(raw, features, gates)
    frame = apply_gates(raw, gates)
    frame["y"] = (frame["label"].astype(str) == spec["label"]).astype(int)
    if frame.empty:
        raise ValueError(f"{name}: no rows after applicability gates")

    probabilities, valid, source_details = leave_one_source_out(frame, features)
    y_valid = frame.loc[valid, "y"].to_numpy(dtype=int)
    p_valid = probabilities[valid]
    source_separated_valid = bool(valid.all()) and len(np.unique(y_valid)) == 2
    if len(y_valid) == 0 or len(np.unique(y_valid)) < 2:
        threshold = 1.0
        validation_metrics = metrics(y_valid, p_valid, threshold)
        precision_passed = False
    else:
        threshold, validation_metrics, precision_passed = select_threshold(
            y_valid, p_valid, target_precision
        )

    y_all = frame["y"].to_numpy(dtype=int)
    model = make_model(y_all)
    model.fit(frame[features], y_all)
    artifact_name = f"{name}.xgb.json"
    artifact_path = output_dir / artifact_name
    model.get_booster().save_model(artifact_path)

    reloaded = xgb.Booster()
    reloaded.load_model(artifact_path)
    matrix = xgb.DMatrix(frame[features], feature_names=features)
    original_predictions = model.get_booster().predict(matrix)
    reloaded_predictions = reloaded.predict(matrix)
    max_reload_delta = float(np.max(np.abs(original_predictions - reloaded_predictions)))
    reload_parity = max_reload_delta <= 1e-7

    standard_mask = (
        frame.get("standard_protocol_verdict", pd.Series("", index=frame.index))
        .fillna("").astype(str).eq("confirmed").to_numpy()
    )
    standard_candidates = int(
        ((probabilities >= threshold) & valid & standard_mask).sum()
    )
    # The unified decision layer always applies standard results first.
    standard_final_overrides = 0
    promoted = (
        source_separated_valid
        and precision_passed
        and validation_metrics["precision"] > target_precision
        and standard_final_overrides == 0
        and reload_parity
    )
    for detail in source_details:
        if not detail.get("valid"):
            continue
        mask = frame["source_file"].astype(str).eq(detail["source"]).to_numpy()
        detail["metrics"] = metrics(frame.loc[mask, "y"].to_numpy(dtype=int), probabilities[mask], threshold)

    return {
        "label": spec["label"],
        "version": model_version,
        "status": "promoted" if promoted else "shadow",
        "file": artifact_name,
        "sha256": sha256(artifact_path),
        "threshold": threshold,
        "features": features,
        "applicability": gates,
        "training": {
            "rows_before_gates": int(len(raw)),
            "rows_after_gates": int(len(frame)),
            "positive_rows": int(frame["y"].sum()),
            "negative_rows": int((frame["y"] == 0).sum()),
            "sources": sorted(frame["source_file"].astype(str).unique().tolist()),
        },
        "validation": {
            "method": "leave_one_source_out",
            "target_precision_strictly_greater_than": target_precision,
            "source_separated_valid": source_separated_valid,
            "metrics": validation_metrics,
            "by_source": source_details,
            "standard_confirmed_candidate_conflicts": standard_candidates,
            "standard_final_override_conflicts": standard_final_overrides,
            "reload_parity": reload_parity,
            "max_reload_probability_delta": max_reload_delta,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="export production vpnflow XGBoost models")
    parser.add_argument("--csv", default="out/trojan_all_samples_features.csv")
    parser.add_argument("--model-dir", default="models")
    parser.add_argument("--version", default=datetime.now(timezone.utc).strftime("baseline-%Y%m%d"))
    parser.add_argument("--target-precision", type=float, default=0.99)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not 0.0 < args.target_precision < 1.0:
        raise SystemExit("--target-precision must be between 0 and 1")
    csv_path = Path(args.csv).resolve()
    destination = Path(args.model_dir).resolve()
    raw = pd.read_csv(csv_path)
    compatibility_aliases: list[str] = []
    if "trojan_applicable" not in raw.columns:
        if "post_tls_payload_ready" not in raw.columns:
            raise SystemExit(
                "training CSV requires trojan_applicable or legacy post_tls_payload_ready"
            )
        raw = pd.concat(
            [raw, raw["post_tls_payload_ready"].rename("trojan_applicable")],
            axis=1,
        ).copy()
        compatibility_aliases.append("trojan_applicable=post_tls_payload_ready")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=destination.name + ".", dir=destination.parent))
    try:
        model_definitions = {
            name: train_one(name, raw, temporary, args.version, args.target_precision)
            for name in ("trojan", "shadowsocks")
        }
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "predictor_version": "unified-predictor-v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "training_data": {
                "file": csv_path.name,
                "sha256": sha256(csv_path),
                "rows": int(len(raw)),
                "compatibility_aliases": compatibility_aliases,
            },
            "dependencies": {
                "python": os.sys.version.split()[0],
                "xgboost": xgb.__version__,
                "pandas": pd.__version__,
                "scikit_learn": sklearn.__version__,
            },
            "models": model_definitions,
        }
        (temporary / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        destination.mkdir(parents=True, exist_ok=True)
        for source in temporary.iterdir():
            os.replace(source, destination / source.name)
        print(json.dumps({
            "model_dir": str(destination),
            "models": {
                name: {
                    "status": definition["status"],
                    "threshold": definition["threshold"],
                    "precision": definition["validation"]["metrics"]["precision"],
                    "recall": definition["validation"]["metrics"]["recall"],
                }
                for name, definition in model_definitions.items()
            },
        }, ensure_ascii=False, indent=2))
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


if __name__ == "__main__":
    main()
