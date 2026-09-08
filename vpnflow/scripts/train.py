#!/usr/bin/env python3
"""VPN/Trojan 流量识别 - Phase 5 训练管线
读 Go 预处理器输出的特征 CSV，XGBoost 二分类（trojan vs clean），
对比多个特征集 + leave-one-source-out 泄漏诊断 + 特征重要性。
"""
import argparse
import os
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

# ===== 特征集（对应 CSV header，计划 §13.4）=====
PROTOCOL_CORE = [
    'flow_duration', 'total_packets', 'total_payload_bytes',
    'uplink_payload_bytes', 'downlink_payload_bytes',
    'bytes_ratio', 'packet_count_ratio', 'pkts_per_second', 'bytes_per_second',
    'ratio_small_100', 'ratio_1514', 'pkt_size_mean', 'pkt_size_std', 'pkt_size_cv',
    'pkt_size_entropy', 'is_bimodal',
    'iat_mean', 'iat_std', 'iat_p50', 'iat_p90', 'burst_ratio',
    'ack_only_ratio', 'zero_payload_ratio', 'psh_ratio',
    'direction_switch_rate', 'uplink_payload_ratio', 'downlink_payload_ratio',
]
FINGERPRINT = [
    'outer_client_hello_present', 'outer_client_hello_size', 'outer_tls_version',
    'outer_cipher_count', 'outer_extension_count', 'outer_has_grease',
    'outer_ja3_hash_int', 'outer_extension_order_hash_int',
]
SEQUENCE = [f'pkt_size_{i}' for i in range(1, 11)] + \
           [f'pkt_dir_{i}' for i in range(1, 11)] + \
           [f'pkt_iat_{i}' for i in range(1, 11)] + ['actual_pkt_count']
OUTER_APPDATA = [f'outer_appdata_len_{i}' for i in range(1, 7)] + \
                ['first_uplink_appdata_size', 'first_downlink_appdata_size', 'first_appdata_ul_to_dl_ms']
INNER = ['inner_hello_count', 'inner_offset_value', 'inner_offset_valid']

FEATURE_SETS = {
    'A_core':           PROTOCOL_CORE,
    'B_fingerprint':    PROTOCOL_CORE + FINGERPRINT,
    'C_sequence':       PROTOCOL_CORE + SEQUENCE + OUTER_APPDATA,
    'E_no_inner':       PROTOCOL_CORE + FINGERPRINT + SEQUENCE + OUTER_APPDATA,
    'D_full':           PROTOCOL_CORE + FINGERPRINT + SEQUENCE + OUTER_APPDATA + INNER,
}


def make_model(spw):
    return xgb.XGBClassifier(
        n_estimators=300, max_depth=4, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=spw, eval_metric='auc',
        n_jobs=4, random_state=42, verbosity=0,
    )


def cv_eval(df, cols, n_splits=5):
    X = df[cols].values
    y = df['y'].values
    skf = StratifiedKFold(n_splits, shuffle=True, random_state=42)
    f1s, aucs, precs, recs = [], [], [], []
    for tr, va in skf.split(X, y):
        spw = (y[tr] == 0).sum() / max((y[tr] == 1).sum(), 1)
        m = make_model(spw)
        m.fit(X[tr], y[tr])
        p = m.predict_proba(X[va])[:, 1]
        pred = (p >= 0.5).astype(int)
        f1s.append(f1_score(y[va], pred, zero_division=0))
        aucs.append(roc_auc_score(y[va], p) if len(set(y[va])) > 1 else 0)
        precs.append(precision_score(y[va], pred, zero_division=0))
        recs.append(recall_score(y[va], pred, zero_division=0))
    return np.mean(f1s), np.mean(aucs), np.mean(precs), np.mean(recs)


def loo_source(df, cols):
    """Leave-One-Source-Out。
    留 clean source: 报告误报率 (clean 被误判 trojan 的比例) + 平均 trojan 概率。
    留 trojan source: 训练集无 trojan, 报告 recall (预期 0, 揭示单 source 泛化问题)。
    """
    sources = sorted(df['source_file'].unique())
    rows = []
    for s in sources:
        tr = df[df['source_file'] != s]
        va = df[df['source_file'] == s]
        va_y = va['y'].values
        if tr['y'].nunique() < 2:
            # 训练集单类（留 trojan source 时训练集只剩 clean）
            rows.append((s, len(va), va_y.mean(), 'train=clean-only', '-', '-', 0.0))
            continue
        spw = (tr['y'] == 0).sum() / max((tr['y'] == 1).sum(), 1)
        m = make_model(spw)
        m.fit(tr[cols].values, tr['y'].values)
        p = m.predict_proba(va[cols].values)[:, 1]
        pred = (p >= 0.5).astype(int)
        mean_prob = p.mean()
        if va_y.sum() == 0:
            # clean source: FP rate (clean 误判 trojan) — 越低越好
            fp = int((pred == 1).sum())
            rows.append((s, len(va), 0.0, f'FP={fp}/{len(va)}', f'{mean_prob:.3f}', '-', mean_prob))
        elif va_y.sum() == len(va):
            rec = recall_score(va_y, pred, zero_division=0)
            rows.append((s, len(va), 1.0, f'recall={rec:.3f}', f'{mean_prob:.3f}', '-', mean_prob))
        else:
            f1 = f1_score(va_y, pred, zero_division=0)
            auc = roc_auc_score(va_y, p)
            rows.append((s, len(va), va_y.mean(), f'F1={f1:.3f}', f'{mean_prob:.3f}', f'{auc:.3f}', mean_prob))
    return rows


def importance(df, cols, top_n=25):
    spw = (df['y'] == 0).sum() / max((df['y'] == 1).sum(), 1)
    m = make_model(spw)
    m.fit(df[cols].values, df['y'].values)
    imp = pd.Series(m.feature_importances_, index=cols).sort_values(ascending=False)
    return imp.head(top_n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', default='/home/lixiao/vpn/features4.csv')
    ap.add_argument('--out', default='/home/lixiao/vpn/reports/train_report.txt')
    ap.add_argument(
        '--allow-missing-post-tls',
        action='store_true',
        help='允许后 TLS 载荷不可用的流进入 Trojan 模型（仅用于对照实验）',
    )
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    total_before_gate = len(df)
    if not args.allow_missing_post_tls:
        gate_col = (
            'trojan_applicable'
            if 'trojan_applicable' in df.columns
            else 'post_tls_payload_ready'
        )
        if gate_col not in df.columns:
            raise ValueError(
                'CSV 缺少 trojan_applicable/post_tls_payload_ready；'
                '请使用新版 vpnflow 重新提取特征'
            )
        df = df[df[gate_col].fillna(0).astype(int) == 1].copy()
        if df.empty:
            raise ValueError('Trojan applicability 门控后没有可训练样本')
    df['y'] = (df['label'] == 'trojan').astype(int)

    lines = []
    def p(s=''):
        print(s)
        lines.append(s)

    p('=' * 72)
    p('Phase 5 训练报告 — Trojan vs Clean 二分类')
    p('=' * 72)
    p(
        f'Trojan applicability gate: '
        f'{"disabled" if args.allow_missing_post_tls else "enabled"}, '
        f'kept={len(df)}/{total_before_gate}'
    )
    p(f'总样本: {len(df)} 流, trojan={df["y"].sum()}, clean={(df["y"]==0).sum()}')
    p('\n按 source 分布:')
    for s, g in df.groupby('source_file'):
        p(f'  {s:24s} n={len(g):4d}  trojan={g["y"].sum():3d}  ({g["y"].mean()*100:.0f}%)')

    p('\n' + '=' * 72)
    p('特征集对比 (5-fold StratifiedKFold by flow)')
    p('注意: 同 source 的流在 train/test, 指标乐观 (尤其 trojan 单 source)')
    p('-' * 72)
    p(f'{"set":18s} {"n_feat":>6s} {"F1":>7s} {"AUC":>7s} {"Prec":>7s} {"Rec":>7s}')
    for name, cols in FEATURE_SETS.items():
        f1, auc, prec, rec = cv_eval(df, cols)
        p(f'{name:18s} {len(cols):6d} {f1:7.4f} {auc:7.4f} {prec:7.4f} {rec:7.4f}')

    p('\n' + '=' * 72)
    p('Leave-One-Source-Out (D_full 特征集)')
    p('留 clean source: FP=误报率(clean 被判 trojan), mean_prob=平均 trojan 概率(越低越好)')
    p('留 trojan source: 训练集无 trojan, recall 预期 0 (单 source 泛化死穴)')
    p('-' * 72)
    p(f'{"source":24s} {"n":>4s} {"trojan%":>8s} {"metric":>18s} {"mean_prob":>10s}')
    for s, n, tf, metric, mp, auc, _ in loo_source(df, FEATURE_SETS['D_full']):
        p(f'{s:24s} {n:4d} {tf*100:7.1f}% {metric:>18s} {mp:>10s}')

    p('\n' + '=' * 72)
    p('特征重要性 Top 25 (D_full, 全量训练)')
    p('-' * 72)
    imp = importance(df, FEATURE_SETS['D_full'])
    mx = imp.max() if imp.max() > 0 else 1
    for name, val in imp.items():
        bar = '#' * int(val * 100 / mx)
        p(f'  {name:32s} {val*100:6.2f}% {bar}')

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    p(f'\n报告已保存: {args.out}')


if __name__ == '__main__':
    main()
