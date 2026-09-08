#!/usr/bin/env python3
"""CPU inference latency/throughput for Trojan CNN vs XGBoost."""
from __future__ import annotations

import io
import statistics
import time
from pathlib import Path

import numpy as np
import torch
import xgboost as xgb
from sklearn.model_selection import train_test_split

from eval_dl_trojan import (
    SEED,
    MLP,
    Normalizer,
    SequenceCNN,
    load_dataset,
    merged_columns,
    set_seed,
    train_model,
    PreparedData,
)


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(round((q / 100) * (len(ordered) - 1)))))
    return ordered[index]


def timed_loop(fn, repeats: int, warmup: int) -> list[float]:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


def summarize(name: str, samples: list[float], items_per_call: int) -> str:
    mean_ms = statistics.mean(samples)
    throughput = items_per_call / (mean_ms / 1000.0)
    return (
        f"{name:28s} n={len(samples):4d}  "
        f"p50={percentile(samples, 50):7.3f}ms  "
        f"p95={percentile(samples, 95):7.3f}ms  "
        f"p99={percentile(samples, 99):7.3f}ms  "
        f"mean={mean_ms:7.3f}ms  "
        f"{throughput:10.0f} flows/s"
    )


def cnn_params(model: torch.nn.Module) -> int:
    return sum(p.numel() for p in model.parameters())


def blob_kb(obj) -> float:
    if isinstance(obj, torch.nn.Module):
        buffer = io.BytesIO()
        torch.save(obj.state_dict(), buffer)
        return buffer.tell() / 1024.0
    booster = obj.get_booster()
    raw = booster.save_raw()
    return len(raw) / 1024.0


def make_xgb(y: np.ndarray, threads: int) -> xgb.XGBClassifier:
    pos = float((y == 1).sum())
    neg = float((y == 0).sum())
    return xgb.XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=neg / max(pos, 1.0),
        eval_metric="auc",
        n_jobs=threads,
        random_state=42,
        verbosity=0,
    )


def prepare_all(frame, columns):
    all_columns, scalar_columns, sequence_channels = columns
    indices = np.arange(len(frame))
    labels = frame["y"].to_numpy(dtype=np.float32)
    scalar_raw = frame[scalar_columns].to_numpy(dtype=np.float32)
    sequence_raw = np.stack(
        [frame[channel].to_numpy(dtype=np.float32) for channel in sequence_channels],
        axis=1,
    )
    merged_raw = frame[all_columns].to_numpy(dtype=np.float32)
    scalar_n = Normalizer.fit(scalar_raw)
    sequence_n = Normalizer.fit(sequence_raw)
    merged_n = Normalizer.fit(merged_raw)
    cnn_data = PreparedData(
        scalar_n.transform(scalar_raw),
        sequence_n.transform(sequence_raw),
        labels,
    )
    mlp_data = PreparedData(
        merged_n.transform(merged_raw),
        np.zeros((len(frame), 1), dtype=np.float32),
        labels,
    )
    return indices, cnn_data, mlp_data, merged_raw


def main() -> None:
    csv_path = "trojan_all_samples_features.csv"
    out_path = Path("trojan_infer_bench.txt")
    try:
        torch.set_num_interop_threads(1)
    except RuntimeError:
        pass
    frame = load_dataset(csv_path)
    columns = merged_columns()
    _, cnn_data, mlp_data, merged_raw = prepare_all(frame, columns)
    y = frame["y"].to_numpy()

    set_seed(SEED)
    train_idx, _ = train_test_split(
        np.arange(len(frame)), test_size=0.18, stratify=y, random_state=SEED
    )
    cnn = train_model("cnn", PreparedData(
        cnn_data.first[train_idx], cnn_data.second[train_idx], cnn_data.labels[train_idx]
    ), SEED)
    mlp = train_model("mlp", PreparedData(
        mlp_data.first[train_idx], mlp_data.second[train_idx], mlp_data.labels[train_idx]
    ), SEED)
    xgb_model = make_xgb(y[train_idx], threads=1)
    xgb_model.fit(merged_raw[train_idx], y[train_idx])

    cnn.eval()
    mlp.eval()
    scalar_all = torch.from_numpy(cnn_data.first)
    sequence_all = torch.from_numpy(cnn_data.second)
    merged_all = torch.from_numpy(mlp_data.first)
    dummy_mlp = torch.from_numpy(mlp_data.second)

    lines = [
        "Trojan inference benchmark on 10.10.3.43 CPU",
        "=" * 78,
        f"rows={len(frame)} feat=133  CNN params={cnn_params(cnn)}  "
        f"MLP params={cnn_params(mlp)}  XGB trees={xgb_model.n_estimators}",
        f"serialized: CNN={blob_kb(cnn):.1f}KB  MLP={blob_kb(mlp):.1f}KB  "
        f"XGB={blob_kb(xgb_model):.1f}KB",
        "timing excludes vpnflow feature extraction",
        "",
    ]

    def run_thread_config(label: str, torch_threads: int, xgb_threads: int) -> None:
        torch.set_num_threads(torch_threads)
        xgb_model.set_params(n_jobs=xgb_threads)
        lines.append(f"{label}: torch_threads={torch_threads}  xgb_n_jobs={xgb_threads}")
        lines.append("-" * 78)

        one = 0
        with torch.no_grad():
            def cnn_one():
                torch.sigmoid(cnn(scalar_all[one:one + 1], sequence_all[one:one + 1]))

            def mlp_one():
                torch.sigmoid(mlp(merged_all[one:one + 1], dummy_mlp[one:one + 1]))

        def xgb_one():
            xgb_model.predict_proba(merged_raw[one:one + 1])

        lines.append(summarize("CNN  single-flow", timed_loop(cnn_one, 800, 50), 1))
        lines.append(summarize("MLP  single-flow", timed_loop(mlp_one, 800, 50), 1))
        lines.append(summarize("XGB  single-flow", timed_loop(xgb_one, 800, 50), 1))

        for batch in (32, 64, 256, len(frame)):
            with torch.no_grad():
                def cnn_batch(b=batch):
                    torch.sigmoid(cnn(scalar_all[:b], sequence_all[:b]))

                def mlp_batch(b=batch):
                    torch.sigmoid(mlp(merged_all[:b], dummy_mlp[:b]))

            def xgb_batch(b=batch):
                xgb_model.predict_proba(merged_raw[:b])

            repeats = 80 if batch < 256 else 40
            lines.append(summarize(f"CNN  batch={batch}", timed_loop(cnn_batch, repeats, 8), batch))
            lines.append(summarize(f"MLP  batch={batch}", timed_loop(mlp_batch, repeats, 8), batch))
            lines.append(summarize(f"XGB  batch={batch}", timed_loop(xgb_batch, repeats, 8), batch))
        lines.append("")

    run_thread_config("online / 1 thread", 1, 1)
    run_thread_config("batch / 8 threads", 8, 8)

    text = "\n".join(lines) + "\n"
    out_path.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
