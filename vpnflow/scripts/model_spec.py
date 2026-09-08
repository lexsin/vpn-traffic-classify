"""Shared feature and applicability specification for production XGBoost models."""
from __future__ import annotations

CORE_FEATURES = [
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


def shape_sequence_features(prefix: str = "") -> list[str]:
    columns = [f"{prefix}{name}" for name in CORE_FEATURES]
    for stem in ("pkt_size", "pkt_dir", "pkt_iat"):
        columns.extend(f"{prefix}{stem}_{i}" for i in range(1, 11))
    columns.append(f"{prefix}actual_pkt_count")
    for stem in ("payload_pkt_size", "payload_pkt_dir", "payload_pkt_iat"):
        columns.extend(f"{prefix}{stem}_{i}" for i in range(1, 11))
    columns.append(f"{prefix}actual_payload_pkt_count")
    return columns


def trojan_features() -> list[str]:
    columns = [f"post_tls_appdata_len_{i}" for i in range(1, 11)]
    columns += [f"post_tls_appdata_dir_{i}" for i in range(1, 11)]
    columns += [f"post_tls_appdata_iat_{i}" for i in range(1, 11)]
    columns += shape_sequence_features("post_tls_shape_")
    assert len(columns) == 133
    return columns


def shadowsocks_features() -> list[str]:
    columns = shape_sequence_features()
    assert len(columns) == 103
    return columns


COMMON_GATES = [
    {"column": "total_packets", "op": "gte", "value": 20},
    {"column": "flow_duration", "op": "gte", "value": 1.0},
    {"column": "total_payload_bytes", "op": "gte", "value": 1000},
    {"column": "payload_packets", "op": "gte", "value": 3},
    {"column": "uplink_packets", "op": "gt", "value": 0},
    {"column": "downlink_packets", "op": "gt", "value": 0},
]

MODEL_SPECS = {
    "trojan": {
        "label": "trojan",
        "features": trojan_features(),
        "applicability": COMMON_GATES + [
            {"column": "trojan_applicable", "op": "eq", "value": 1},
        ],
    },
    "shadowsocks": {
        "label": "shadowsocks",
        "features": shadowsocks_features(),
        "applicability": COMMON_GATES + [
            {"column": "tcp_handshake_complete", "op": "eq", "value": 1},
        ],
    },
}
