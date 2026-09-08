#!/usr/bin/env python3
"""XGBoost eval aligned with evalss: post-TLS filter + trojan_post_tls_merged."""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold

THRESHOLD = 0.6
CORE = [
    "flow_duration", "total_packets", "total_payload_bytes",
    "uplink_payload_bytes", "downlink_payload_bytes",
    "uplink_packets", "downlink_packets",
    "payload_packets", "uplink_payload_packets", "downlink_payload_packets",
    "bytes_ratio", "packet_count_ratio", "payload_packet_ratio",
    "pkts_per_second", "bytes_per_second", "payload_bytes_per_second",
    "ratio_small_100", "ratio_1514", "pkt_size_mean", "pkt_size_std", "pkt_size_cv",
    "pkt_size_entropy", "is_bimodal",
    "payload_size_mean", "payload_size_std", "payload_size_cv", "payload_size_entropy",
    "avg_payload_bytes_per_payload_pkt", "avg_uplink_payload_bytes_per_pkt",
    "avg_downlink_payload_bytes_per_pkt",
    "iat_mean", "iat_std", "iat_p50", "iat_p90", "burst_ratio",
    "ack_only_ratio", "zero_payload_ratio", "psh_ratio",
    "direction_switch_rate", "uplink_payload_ratio", "downlink_payload_ratio",
]


def merged_columns(header: list[str]) -> list[str]:
    seq = [f"post_tls_appdata_len_{i}" for i in range(1, 11)]
    seq += [f"post_tls_appdata_dir_{i}" for i in range(1, 11)]
    seq += [f"post_tls_appdata_iat_{i}" for i in range(1, 11)]
    shape_src = list(CORE)
    for i in range(1, 11):
        shape_src.append(f"pkt_size_{i}")
    for i in range(1, 11):
        shape_src.append(f"pkt_dir_{i}")
    for i in range(1, 11):
        shape_src.append(f"pkt_iat_{i}")
    shape_src.append("actual_pkt_count")
    for i in range(1, 11):
        shape_src.append(f"payload_pkt_size_{i}")
    for i in range(1, 11):
        shape_src.append(f"payload_pkt_dir_{i}")
    for i in range(1, 11):
        shape_src.append(f"payload_pkt_iat_{i}")
    shape_src.append("actual_payload_pkt_count")
    shape = [f"post_tls_shape_{c}" for c in shape_src]
    cols = [c for c in seq + shape if c in header]
    if len(cols) != 133:
        raise SystemExit(f"merged columns={len(cols)}, want 133")
    return cols


def keep_row(r: pd.Series, require_post_tls: bool) -> bool:
    if int(r["total_packets"]) < 20:
        return False
    if float(r["flow_duration"]) < 1.0:
        return False
    if int(r["total_payload_bytes"]) < 1000:
        return False
    payload_pkts = int(r["payload_packets"]) if "payload_packets" in r.index else 0
    if payload_pkts == 0:
        payload_pkts = int(round(int(r["total_packets"]) * (1 - float(r["zero_payload_ratio"]))))
    if payload_pkts < 3:
        return False
    if int(r["uplink_packets"]) == 0 or int(r["downlink_packets"]) == 0:
        return False
    if require_post_tls and int(r.get("post_tls_payload_ready", 0)) != 1:
        return False
    return True


def family(label: str) -> str:
    if label == "clean":
        return "https_clean"
    if label == "vmess_vless":
        return "vless"
    return label


def make_model(y: np.ndarray) -> xgb.XGBClassifier:
    pos = int((y == 1).sum())
    neg = int((y == 0).sum())
    spw = neg / max(pos, 1)
    return xgb.XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=spw,
        eval_metric="auc",
        n_jobs=4,
        random_state=42,
        verbosity=0,
    )


def metrics(y: np.ndarray, p: np.ndarray) -> dict:
    pred = (p >= THRESHOLD).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    f1 = 2 * prec * rec / max(prec + rec, 1e-12)
    auc = 0.0
    if y.min() != y.max():
        auc = float(roc_auc_score(y, p))
    return {
        "n": len(y), "pos": int(y.sum()),
        "f1": f1, "auc": auc, "prec": prec, "rec": rec,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "meanp": float(p.mean()),
    }


def fmt(m: dict) -> str:
    return (
        f"F1={m['f1']:.4f} AUC={m['auc']:.4f} Prec={m['prec']:.4f} Rec={m['rec']:.4f} "
        f"TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}"
    )


def cv_oof(X: np.ndarray, y: np.ndarray) -> np.ndarray:
    oof = np.zeros(len(y))
    skf = StratifiedKFold(5, shuffle=True, random_state=42)
    for tr, va in skf.split(X, y):
        m = make_model(y[tr])
        m.fit(X[tr], y[tr])
        oof[va] = m.predict_proba(X[va])[:, 1]
    return oof


def loo(df: pd.DataFrame, cols: list[str]) -> tuple[np.ndarray, list[tuple[str, dict]]]:
    y = df["y"].to_numpy()
    p = np.zeros(len(df))
    detail = []
    for src in sorted(df["source_file"].unique()):
        tr = df["source_file"] != src
        va = ~tr
        if df.loc[tr, "y"].nunique() < 2:
            p[va.to_numpy()] = 0.0
            m = metrics(y[va.to_numpy()], p[va.to_numpy()])
            detail.append((src, m))
            continue
        model = make_model(df.loc[tr, "y"].to_numpy())
        model.fit(df.loc[tr, cols], df.loc[tr, "y"])
        pv = model.predict_proba(df.loc[va, cols])[:, 1]
        p[va.to_numpy()] = pv
        detail.append((src, metrics(y[va.to_numpy()], pv)))
    return p, detail


def family_table(df: pd.DataFrame, p: np.ndarray) -> list[str]:
    lines = []
    pred = (p >= THRESHOLD).astype(int)
    y = df["y"].to_numpy()
    fams = df["family"].to_numpy()
    order = ["https_clean", "vless", "pptp", "l2tp", "openvpn", "shadowsocks", "trojan"]
    present = [f for f in order if f in set(fams)]
    lines.append(f"{'family':16s} {'n':>5} {'pos':>5} {'FP':>5} {'FP%':>7} {'FN':>5} {'meanP':>8}")
    for fam in present:
        mask = fams == fam
        n = int(mask.sum())
        pos = int(y[mask].sum())
        fp = int(((pred[mask] == 1) & (y[mask] == 0)).sum())
        fn = int(((pred[mask] == 0) & (y[mask] == 1)).sum())
        neg = n - pos
        fpct = 100 * fp / max(neg, 1)
        lines.append(f"{fam:16s} {n:5d} {pos:5d} {fp:5d} {fpct:6.1f}% {fn:5d} {p[mask].mean():8.4f}")
    return lines


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="out/trojan_all_samples_features.csv")
    ap.add_argument("--out", default="out/trojan_post_tls_merged_xgb_report.txt")
    args = ap.parse_args()

    raw = pd.read_csv(args.csv)
    cols = merged_columns(list(raw.columns))
    raw["y"] = (raw["label"] == "trojan").astype(int)
    raw["family"] = raw["label"].map(family)

    post = raw[raw.apply(lambda r: keep_row(r, True), axis=1)].reset_index(drop=True)
    rest = raw[raw.apply(lambda r: keep_row(r, False), axis=1)]
    rest = rest[rest["post_tls_payload_ready"].fillna(0).astype(int) != 1].reset_index(drop=True)

    lines = []
    p = lambda s: lines.append(s)

    p("XGBoost vs evalss-LR  (trojan_post_tls_merged, post-TLS filter, threshold=0.6)")
    p("=" * 72)
    p(f"rows={len(post)} positive={int(post.y.sum())} negative={int((post.y==0).sum())} feat={len(cols)}")
    p("")
    p("source distribution:")
    for src, g in post.groupby("source_file"):
        p(f"  {src:45s} n={len(g):4d} pos={int(g.y.sum()):3d} family={g.family.iloc[0]}")

    X = post[cols].to_numpy(dtype=float)
    y = post["y"].to_numpy()
    oof = cv_oof(X, y)
    p("")
    p("5-fold OOF (StratifiedKFold seed=42)")
    p("-" * 72)
    p("xgb_merged                       " + fmt(metrics(y, oof)))

    loo_p, loo_detail = loo(post, cols)
    p("")
    p("Leave-one-source-out aggregate")
    p("-" * 72)
    p("xgb_merged                       " + fmt(metrics(y, loo_p)))

    p("")
    p("LOO by source")
    p("-" * 72)
    for src, m in loo_detail:
        fam = post.loc[post.source_file == src, "family"].iloc[0]
        p(f"  {src:45s} fam={fam:12s} n={m['n']:4d} {fmt(m)}")

    p("")
    p("LOO false positives by protocol family (hypothesis: other VPNs misclassified more)")
    p("-" * 72)
    lines.extend(family_table(post, loo_p))

    model = make_model(y)
    model.fit(post[cols], post["y"])
    imp = pd.Series(model.feature_importances_, index=cols).sort_values(ascending=False)
    p("")
    p("XGBoost gain importance (top 20, trained on all post-TLS rows)")
    p("-" * 72)
    for name, val in imp.head(20).items():
        p(f"  {name:40s} {val:8.4f}")

    p("")
    p("External: train on post-TLS 760, score typical flows WITHOUT post-TLS window")
    p("-" * 72)
    p(f"unscored_zero_window rows={len(rest)}")
    if len(rest) > 0:
        pe = model.predict_proba(rest[cols])[:, 1]
        rest = rest.copy()
        rest["p"] = pe
        p("These rows would be all-zero / empty post-TLS features (SS, OpenVPN, SSH, ...).")
        lines.extend(family_table(rest.assign(y=(rest.label == "trojan").astype(int)), pe))
        p("by source:")
        for src, g in rest.groupby("source_file"):
            fp = int(((g.p >= THRESHOLD) & (g.y == 0)).sum()) if "y" in g else int((g.p >= THRESHOLD).sum())
            # rest y from label
            yy = (g.label != "trojan").sum()  # noqa: unused, keep meanp
            n = len(g)
            fp = int((g.p >= THRESHOLD).sum())  # all should be negative
            p(f"  {src:45s} lab={g.label.iloc[0]:12s} n={n:4d} pred_pos={fp:4d} meanP={g.p.mean():.4f}")

    text = "\n".join(lines) + "\n"
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
