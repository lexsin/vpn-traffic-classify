#!/usr/bin/env python3
"""Evaluate Shadowsocks shape_sequence features with XGBoost."""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold

THRESHOLD = 0.6
STANDARD_PROTOCOLS = {"openvpn", "pptp", "l2tp"}

CORE = [
    "flow_duration", "total_packets", "total_payload_bytes",
    "uplink_payload_bytes", "downlink_payload_bytes",
    "uplink_packets", "downlink_packets",
    "payload_packets", "uplink_payload_packets", "downlink_payload_packets",
    "bytes_ratio", "packet_count_ratio", "payload_packet_ratio",
    "pkts_per_second", "bytes_per_second", "payload_bytes_per_second",
    "ratio_small_100", "ratio_1514", "pkt_size_mean", "pkt_size_std",
    "pkt_size_cv", "pkt_size_entropy", "is_bimodal",
    "payload_size_mean", "payload_size_std", "payload_size_cv",
    "payload_size_entropy", "avg_payload_bytes_per_payload_pkt",
    "avg_uplink_payload_bytes_per_pkt", "avg_downlink_payload_bytes_per_pkt",
    "iat_mean", "iat_std", "iat_p50", "iat_p90", "burst_ratio",
    "ack_only_ratio", "zero_payload_ratio", "psh_ratio",
    "direction_switch_rate", "uplink_payload_ratio", "downlink_payload_ratio",
]


def shape_sequence_columns() -> list[str]:
    cols = list(CORE)
    for stem in ("pkt_size", "pkt_dir", "pkt_iat"):
        cols.extend(f"{stem}_{i}" for i in range(1, 11))
    cols.append("actual_pkt_count")
    for stem in ("payload_pkt_size", "payload_pkt_dir", "payload_pkt_iat"):
        cols.extend(f"{stem}_{i}" for i in range(1, 11))
    cols.append("actual_payload_pkt_count")
    return cols


def load_filtered(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    payload_packets = df["payload_packets"].copy()
    missing = payload_packets == 0
    payload_packets.loc[missing] = np.rint(
        df.loc[missing, "total_packets"]
        * (1 - df.loc[missing, "zero_payload_ratio"])
    )
    keep = (
        (df["total_packets"] >= 20)
        & (df["flow_duration"] >= 1)
        & (df["total_payload_bytes"] >= 1000)
        & (payload_packets >= 3)
        & (df["uplink_packets"] > 0)
        & (df["downlink_packets"] > 0)
        & (df["tcp_handshake_complete"] == 1)
    )
    df = df.loc[keep].copy().reset_index(drop=True)
    df["y"] = (df["label"] == "shadowsocks").astype(int)
    return df


def make_model(y: np.ndarray) -> xgb.XGBClassifier:
    positives = int((y == 1).sum())
    negatives = int((y == 0).sum())
    return xgb.XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=negatives / max(positives, 1),
        eval_metric="auc",
        n_jobs=4,
        random_state=42,
        verbosity=0,
    )


def metrics(y: np.ndarray, probabilities: np.ndarray) -> dict[str, float | int]:
    predictions = (probabilities >= THRESHOLD).astype(int)
    tp = int(((predictions == 1) & (y == 1)).sum())
    fp = int(((predictions == 1) & (y == 0)).sum())
    tn = int(((predictions == 0) & (y == 0)).sum())
    fn = int(((predictions == 0) & (y == 1)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    auc = float(roc_auc_score(y, probabilities)) if len(np.unique(y)) > 1 else 0.0
    return {
        "n": len(y), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1, "auc": auc,
        "mean_probability": float(probabilities.mean()),
    }


def metric_line(result: dict[str, float | int]) -> str:
    return (
        f"F1={result['f1']:.4f} AUC={result['auc']:.4f} "
        f"Prec={result['precision']:.4f} Recall={result['recall']:.4f} "
        f"TP={result['tp']} FP={result['fp']} TN={result['tn']} FN={result['fn']}"
    )


def cross_validation(
    df: pd.DataFrame, features: list[str]
) -> tuple[np.ndarray, dict[str, float | int]]:
    x = df[features].to_numpy(dtype=float)
    y = df["y"].to_numpy()
    probabilities = np.zeros(len(df))
    folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for train, validation in folds.split(x, y):
        model = make_model(y[train])
        model.fit(x[train], y[train])
        probabilities[validation] = model.predict_proba(x[validation])[:, 1]
    return probabilities, metrics(y, probabilities)


def leave_one_source_out(
    df: pd.DataFrame, features: list[str]
) -> tuple[np.ndarray, list[tuple[str, dict[str, float | int]]]]:
    probabilities = np.zeros(len(df))
    details = []
    for source in sorted(df["source_file"].unique()):
        validation = df["source_file"] == source
        train = ~validation
        model = make_model(df.loc[train, "y"].to_numpy())
        model.fit(df.loc[train, features], df.loc[train, "y"])
        source_probabilities = model.predict_proba(
            df.loc[validation, features]
        )[:, 1]
        probabilities[validation.to_numpy()] = source_probabilities
        details.append((
            source,
            metrics(df.loc[validation, "y"].to_numpy(), source_probabilities),
        ))
    return probabilities, details


def protocol_rows(df: pd.DataFrame, probabilities: np.ndarray) -> list[str]:
    rows = [
        f"{'protocol':16s} {'n':>5} {'FP':>5} {'FP%':>7} "
        f"{'FN':>5} {'meanP':>8}"
    ]
    predictions = probabilities >= THRESHOLD
    labels = list(df["label"].unique())
    order = [
        "clean", "trojan", "vmess_vless", "openvpn", "pptp",
        "l2tp", "shadowsocks",
    ]
    for label in [item for item in order if item in labels]:
        mask = (df["label"] == label).to_numpy()
        y = df.loc[mask, "y"].to_numpy()
        fp = int((predictions[mask] & (y == 0)).sum())
        fn = int(((~predictions[mask]) & (y == 1)).sum())
        negatives = int((y == 0).sum())
        rows.append(
            f"{label:16s} {int(mask.sum()):5d} {fp:5d} "
            f"{100 * fp / max(negatives, 1):6.1f}% {fn:5d} "
            f"{probabilities[mask].mean():8.4f}"
        )
    return rows


def evaluate_variant(
    name: str, df: pd.DataFrame, features: list[str], lines: list[str]
) -> tuple[xgb.XGBClassifier, np.ndarray]:
    lines.append("")
    lines.append(name)
    lines.append("=" * 78)
    lines.append(
        f"rows={len(df)} positive={int(df.y.sum())} "
        f"negative={int((df.y == 0).sum())} features={len(features)}"
    )
    _, cv_result = cross_validation(df, features)
    lines.append("5-fold OOF: " + metric_line(cv_result))

    loo_probabilities, details = leave_one_source_out(df, features)
    loo_result = metrics(df["y"].to_numpy(), loo_probabilities)
    lines.append("LOO aggregate: " + metric_line(loo_result))
    lines.append("LOO by protocol:")
    lines.extend(protocol_rows(df, loo_probabilities))
    lines.append("LOO standard protocol sources:")
    for source, result in details:
        label = df.loc[df.source_file == source, "label"].iloc[0]
        if label in STANDARD_PROTOCOLS:
            lines.append(
                f"  {source:40s} label={label:8s} "
                f"n={result['n']:3d} FP={result['fp']:3d} "
                f"meanP={result['mean_probability']:.4f}"
            )

    model = make_model(df["y"].to_numpy())
    model.fit(df[features], df["y"])
    return model, loo_probabilities


def score_external(
    model: xgb.XGBClassifier,
    path: str,
    features: list[str],
    lines: list[str],
    model_name: str,
) -> None:
    external = load_filtered(path)
    probabilities = model.predict_proba(external[features])[:, 1]
    result = metrics(external["y"].to_numpy(), probabilities)
    lines.append("")
    lines.append(f"External scoring: {model_name}")
    lines.append("=" * 78)
    lines.append(f"path={path}")
    lines.append(metric_line(result))
    lines.append(
        f"meanP={result['mean_probability']:.4f} threshold={THRESHOLD:.2f}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="out/trojan_all_samples_features.csv")
    parser.add_argument(
        "--external-csv",
        default="out/external_147182_features_with_handshake.csv",
    )
    parser.add_argument(
        "--out", default="out/ss_all_protocols_shape_sequence_xgb_report.txt"
    )
    args = parser.parse_args()

    features = shape_sequence_columns()
    full = load_filtered(args.csv)
    missing = [column for column in features if column not in full.columns]
    if missing:
        raise SystemExit(f"missing shape_sequence columns: {missing}")
    without_standard = full.loc[
        ~full["label"].isin(STANDARD_PROTOCOLS)
    ].reset_index(drop=True)

    lines = [
        "Shadowsocks XGBoost shape_sequence evaluation",
        f"filter: complete TCP handshake; no ClientHello/post-TLS requirement; threshold={THRESHOLD}",
    ]
    baseline_model, _ = evaluate_variant(
        "Ablation: without OpenVPN/PPTP/L2TP",
        without_standard,
        features,
        lines,
    )
    full_model, _ = evaluate_variant(
        "All protocols: with OpenVPN/PPTP/L2TP", full, features, lines
    )
    if Path(args.external_csv).exists():
        score_external(
            baseline_model, args.external_csv, features, lines,
            "without OpenVPN/PPTP/L2TP",
        )
        score_external(
            full_model, args.external_csv, features, lines,
            "with OpenVPN/PPTP/L2TP",
        )
    else:
        lines.append(f"external CSV not found: {args.external_csv}")

    importance = pd.Series(
        full_model.feature_importances_, index=features
    ).sort_values(ascending=False)
    lines.append("")
    lines.append("All-protocol XGBoost feature importance (top 20)")
    lines.append("=" * 78)
    for feature, value in importance.head(20).items():
        lines.append(f"  {feature:36s} {value:.6f}")

    text = "\n".join(lines) + "\n"
    Path(args.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
