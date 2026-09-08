#!/usr/bin/env python3
"""Trojan MLP and sequence-aware 1D-CNN evaluation."""
from __future__ import annotations

import argparse
import copy
import random
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold, train_test_split
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

SEED = 42
THRESHOLD = 0.6

SHAPE_CORE = [
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


def merged_columns() -> tuple[list[str], list[str], list[list[str]]]:
    record_columns = [
        [f"post_tls_appdata_{kind}_{i}" for i in range(1, 11)]
        for kind in ("len", "dir", "iat")
    ]
    packet_columns = [
        [f"post_tls_shape_{kind}_{i}" for i in range(1, 11)]
        for kind in ("pkt_size", "pkt_dir", "pkt_iat")
    ]
    payload_columns = [
        [f"post_tls_shape_{kind}_{i}" for i in range(1, 11)]
        for kind in ("payload_pkt_size", "payload_pkt_dir", "payload_pkt_iat")
    ]
    sequence_channels = record_columns + packet_columns + payload_columns
    scalar_columns = [f"post_tls_shape_{name}" for name in SHAPE_CORE]
    scalar_columns += [
        "post_tls_shape_actual_pkt_count",
        "post_tls_shape_actual_payload_pkt_count",
    ]
    all_columns = [
        column for channel in sequence_channels for column in channel
    ] + scalar_columns
    return all_columns, scalar_columns, sequence_channels


def load_dataset(path: str) -> pd.DataFrame:
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
        & (df["post_tls_payload_ready"] == 1)
    )
    result = df.loc[keep].copy().reset_index(drop=True)
    result["y"] = (result["label"] == "trojan").astype(np.float32)
    return result


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)


@dataclass
class Normalizer:
    mean: np.ndarray
    std: np.ndarray

    @classmethod
    def fit(cls, values: np.ndarray) -> "Normalizer":
        mean = values.mean(axis=0)
        std = values.std(axis=0)
        std[std < 1e-6] = 1.0
        return cls(mean, std)

    def transform(self, values: np.ndarray) -> np.ndarray:
        return ((values - self.mean) / self.std).astype(np.float32)


class MLP(nn.Module):
    def __init__(self, input_size: int) -> None:
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.ReLU(),
            nn.Dropout(0.25),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.20),
            nn.Linear(32, 1),
        )

    def forward(
        self, features: torch.Tensor, _: torch.Tensor
    ) -> torch.Tensor:
        return self.network(features).squeeze(1)


class SequenceCNN(nn.Module):
    """Convolve nine semantic channels, then fuse post-TLS scalar features."""

    def __init__(self, scalar_size: int) -> None:
        super().__init__()
        self.sequence = nn.Sequential(
            nn.Conv1d(9, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(32, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1),
        )
        self.scalar = nn.Sequential(
            nn.Linear(scalar_size, 32),
            nn.ReLU(),
            nn.Dropout(0.20),
        )
        self.output = nn.Sequential(
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.25),
            nn.Linear(32, 1),
        )

    def forward(
        self, scalar: torch.Tensor, sequence: torch.Tensor
    ) -> torch.Tensor:
        sequence_embedding = self.sequence(sequence).squeeze(2)
        scalar_embedding = self.scalar(scalar)
        return self.output(
            torch.cat((sequence_embedding, scalar_embedding), dim=1)
        ).squeeze(1)


@dataclass
class PreparedData:
    first: np.ndarray
    second: np.ndarray
    labels: np.ndarray


def prepare(
    frame: pd.DataFrame,
    train_indices: np.ndarray,
    test_indices: np.ndarray,
    model_name: str,
    all_columns: list[str],
    scalar_columns: list[str],
    sequence_channels: list[list[str]],
) -> tuple[PreparedData, PreparedData]:
    labels = frame["y"].to_numpy(dtype=np.float32)
    if model_name == "mlp":
        raw = frame[all_columns].to_numpy(dtype=np.float32)
        normalizer = Normalizer.fit(raw[train_indices])
        values = normalizer.transform(raw)
        empty = np.zeros((len(frame), 1), dtype=np.float32)
        return (
            PreparedData(values[train_indices], empty[train_indices],
                         labels[train_indices]),
            PreparedData(values[test_indices], empty[test_indices],
                         labels[test_indices]),
        )

    scalar_raw = frame[scalar_columns].to_numpy(dtype=np.float32)
    sequence_raw = np.stack(
        [frame[channel].to_numpy(dtype=np.float32)
         for channel in sequence_channels],
        axis=1,
    )
    scalar_normalizer = Normalizer.fit(scalar_raw[train_indices])
    sequence_normalizer = Normalizer.fit(sequence_raw[train_indices])
    scalar = scalar_normalizer.transform(scalar_raw)
    sequence = sequence_normalizer.transform(sequence_raw)
    return (
        PreparedData(scalar[train_indices], sequence[train_indices],
                     labels[train_indices]),
        PreparedData(scalar[test_indices], sequence[test_indices],
                     labels[test_indices]),
    )


def subset(data: PreparedData, indices: np.ndarray) -> PreparedData:
    return PreparedData(
        data.first[indices], data.second[indices], data.labels[indices]
    )


def make_loader(
    data: PreparedData, shuffle: bool, batch_size: int = 64
) -> DataLoader:
    dataset = TensorDataset(
        torch.from_numpy(data.first),
        torch.from_numpy(data.second),
        torch.from_numpy(data.labels),
    )
    return DataLoader(dataset, batch_size=batch_size, shuffle=shuffle)


def predict(model: nn.Module, data: PreparedData) -> np.ndarray:
    model.eval()
    output = []
    with torch.no_grad():
        for first, second, _ in make_loader(data, False, 256):
            output.append(torch.sigmoid(model(first, second)).numpy())
    return np.concatenate(output)


def train_model(
    model_name: str, train_data: PreparedData, seed: int
) -> nn.Module:
    set_seed(seed)
    indices = np.arange(len(train_data.labels))
    train_indices, validation_indices = train_test_split(
        indices,
        test_size=0.18,
        stratify=train_data.labels,
        random_state=seed,
    )
    fit_data = subset(train_data, train_indices)
    validation_data = subset(train_data, validation_indices)

    if model_name == "mlp":
        model: nn.Module = MLP(train_data.first.shape[1])
    else:
        model = SequenceCNN(train_data.first.shape[1])

    positives = float(fit_data.labels.sum())
    negatives = len(fit_data.labels) - positives
    loss_function = nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor(negatives / max(positives, 1.0))
    )
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=1e-3, weight_decay=1e-4
    )

    best_state = copy.deepcopy(model.state_dict())
    best_loss = float("inf")
    stale_epochs = 0
    for _ in range(160):
        model.train()
        for first, second, labels in make_loader(fit_data, True):
            optimizer.zero_grad()
            loss = loss_function(model(first, second), labels)
            loss.backward()
            optimizer.step()

        model.eval()
        validation_losses = []
        with torch.no_grad():
            for first, second, labels in make_loader(
                validation_data, False, 256
            ):
                validation_losses.append(
                    float(loss_function(model(first, second), labels))
                )
        validation_loss = float(np.mean(validation_losses))
        if validation_loss < best_loss - 1e-4:
            best_loss = validation_loss
            best_state = copy.deepcopy(model.state_dict())
            stale_epochs = 0
        else:
            stale_epochs += 1
            if stale_epochs >= 18:
                break
    model.load_state_dict(best_state)
    return model


def calculate_metrics(
    labels: np.ndarray, probabilities: np.ndarray,
    threshold: float = THRESHOLD,
) -> dict[str, float | int]:
    predictions = probabilities >= threshold
    positive = labels == 1
    tp = int((predictions & positive).sum())
    fp = int((predictions & ~positive).sum())
    tn = int((~predictions & ~positive).sum())
    fn = int((~predictions & positive).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    auc = (
        float(roc_auc_score(labels, probabilities))
        if len(np.unique(labels)) > 1 else 0.0
    )
    return {
        "f1": f1, "auc": auc, "precision": precision, "recall": recall,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def format_metrics(metrics: dict[str, float | int]) -> str:
    return (
        f"F1={metrics['f1']:.4f} AUC={metrics['auc']:.4f} "
        f"Prec={metrics['precision']:.4f} Recall={metrics['recall']:.4f} "
        f"TP={metrics['tp']} FP={metrics['fp']} "
        f"TN={metrics['tn']} FN={metrics['fn']}"
    )


def run_five_fold(
    frame: pd.DataFrame,
    model_name: str,
    columns: tuple[list[str], list[str], list[list[str]]],
) -> np.ndarray:
    labels = frame["y"].to_numpy()
    probabilities = np.zeros(len(frame), dtype=np.float32)
    folds = StratifiedKFold(5, shuffle=True, random_state=SEED)
    for fold, (train_indices, test_indices) in enumerate(
        folds.split(frame, labels)
    ):
        train_data, test_data = prepare(
            frame, train_indices, test_indices, model_name, *columns
        )
        model = train_model(model_name, train_data, SEED + fold)
        probabilities[test_indices] = predict(model, test_data)
    return probabilities


def run_loo(
    frame: pd.DataFrame,
    model_name: str,
    columns: tuple[list[str], list[str], list[list[str]]],
) -> tuple[np.ndarray, list[tuple[str, dict[str, float | int]]]]:
    probabilities = np.zeros(len(frame), dtype=np.float32)
    details = []
    for fold, source in enumerate(sorted(frame["source_file"].unique())):
        test_mask = (frame["source_file"] == source).to_numpy()
        test_indices = np.flatnonzero(test_mask)
        train_indices = np.flatnonzero(~test_mask)
        train_data, test_data = prepare(
            frame, train_indices, test_indices, model_name, *columns
        )
        model = train_model(model_name, train_data, SEED + fold)
        source_probabilities = predict(model, test_data)
        probabilities[test_indices] = source_probabilities
        detail = calculate_metrics(
            frame.loc[test_indices, "y"].to_numpy(), source_probabilities
        )
        details.append((source, detail))
    return probabilities, details


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--csv", default="trojan_all_samples_features.csv"
    )
    parser.add_argument("--out", default="trojan_dl_report.txt")
    parser.add_argument("--threads", type=int, default=8)
    args = parser.parse_args()

    torch.set_num_threads(args.threads)
    frame = load_dataset(args.csv)
    columns = merged_columns()
    missing = [
        column for column in columns[0] if column not in frame.columns
    ]
    if missing:
        raise SystemExit(f"missing merged columns: {missing}")

    lines = [
        "Trojan deep-learning experiment",
        "=" * 78,
        "post-TLS filter; merged 133 features; threshold=0.6",
        f"rows={len(frame)} positive={int(frame.y.sum())} "
        f"negative={int((frame.y == 0).sum())}",
    ]
    for model_name in ("mlp", "cnn"):
        lines += ["", model_name.upper(), "-" * 78]
        five_fold = run_five_fold(frame, model_name, columns)
        lines.append(
            "5-fold: "
            + format_metrics(
                calculate_metrics(frame["y"].to_numpy(), five_fold)
            )
        )
        loo, details = run_loo(frame, model_name, columns)
        lines.append(
            "LOO:      "
            + format_metrics(calculate_metrics(frame["y"].to_numpy(), loo))
        )
        lines.append("LOO positive sources:")
        for source, result in details:
            if frame.loc[frame.source_file == source, "y"].iloc[0] == 1:
                lines.append(
                    f"  {source:42s} {format_metrics(result)}"
                )
        lines.append("LOO threshold sweep:")
        for threshold in (0.5, 0.6, 0.7, 0.8, 0.9):
            result = calculate_metrics(
                frame["y"].to_numpy(), loo, threshold
            )
            lines.append(
                f"  threshold={threshold:.1f} {format_metrics(result)}"
            )

    text = "\n".join(lines) + "\n"
    Path(args.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
