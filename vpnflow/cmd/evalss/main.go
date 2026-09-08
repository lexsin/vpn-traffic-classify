package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type dataset struct {
	header []string
	rows   []map[string]string
	y      []int
}

type readOptions struct {
	minPackets            int
	minDuration           float64
	minPayloadBytes       int
	minPayloadPkts        int
	requireBidi           bool
	requireClientHello    bool
	requirePostTLSPayload bool
	requireTCPHandshake   bool
	positiveLabel         string
}

type metrics struct {
	n         int
	pos       int
	precision float64
	recall    float64
	f1        float64
	auc       float64
	meanProb  float64
	tp        int
	fp        int
	tn        int
	fn        int
}

var decisionThreshold = 0.6

func main() {
	csvPath := flag.String("csv", filepath.Join("out", "ss_clean.csv"), "feature CSV")
	outPath := flag.String("out", filepath.Join("out", "ss_eval_report.txt"), "report path")
	externalPath := flag.String("external-csv", "", "optional external CSV to score with models trained on --csv")
	predictionOut := flag.String("prediction-out", "", "optional CSV path for per-flow predictions from --model-feature-set on --external-csv")
	modelFeatureSet := flag.String("model-feature-set", "protocol_no_ids", "feature set used for detailed evaluation and per-flow predictions")
	positiveLabel := flag.String("positive-label", "shadowsocks", "label treated as positive class")
	minPackets := flag.Int("min-train-packets", 20, "training-side minimum total packets")
	minDuration := flag.Float64("min-train-duration", 1.0, "training-side minimum flow duration seconds")
	minPayloadBytes := flag.Int("min-train-payload-bytes", 1000, "training-side minimum total payload bytes")
	minPayloadPkts := flag.Int("min-train-payload-pkts", 3, "training-side minimum packets with payload, estimated from zero_payload_ratio")
	requireBidi := flag.Bool("train-require-bidi", true, "training-side require bidirectional packet counts")
	requireClientHello := flag.Bool("train-require-client-hello", false, "training/scoring-side require a parsed TLS ClientHello")
	requirePostTLSPayload := flag.Bool("train-require-post-tls-payload", false, "training/scoring-side require at least 3 records after the outer TLS handshake")
	requireTCPHandshake := flag.Bool("train-require-tcp-handshake", false, "training/scoring-side require a validated TCP three-way handshake")
	threshold := flag.Float64("threshold", 0.6, "positive-class probability threshold used for metrics and per-flow predictions")
	flag.Parse()
	if *threshold <= 0 || *threshold >= 1 {
		fatal(fmt.Errorf("threshold must be between 0 and 1, got %.6f", *threshold))
	}
	decisionThreshold = *threshold

	opts := readOptions{
		minPackets:            *minPackets,
		minDuration:           *minDuration,
		minPayloadBytes:       *minPayloadBytes,
		minPayloadPkts:        *minPayloadPkts,
		requireBidi:           *requireBidi,
		requireClientHello:    *requireClientHello,
		requirePostTLSPayload: *requirePostTLSPayload,
		requireTCPHandshake:   *requireTCPHandshake,
		positiveLabel:         *positiveLabel,
	}

	ds, err := readDataset(*csvPath, opts)
	if err != nil {
		fatal(err)
	}

	sets := featureSets(ds.header)
	selectedCols, ok := sets[*modelFeatureSet]
	if !ok {
		fatal(fmt.Errorf("unknown model-feature-set %q; choose shape_core, shape_sequence, protocol_no_ids, trojan_post_tls_sequence, trojan_post_tls_shape_sequence, or trojan_post_tls_merged", *modelFeatureSet))
	}
	if *modelFeatureSet == "trojan_post_tls_sequence" && len(selectedCols) != 30 {
		fatal(fmt.Errorf("CSV %s 缺少 Trojan 后 TLS 载荷特征列；请使用新版 vpnflow 从 PCAP 重新生成特征", *csvPath))
	}
	if *modelFeatureSet == "trojan_post_tls_shape_sequence" && len(selectedCols) != 103 {
		fatal(fmt.Errorf("CSV %s 缺少 Trojan 后 TLS 握手 shape_sequence 特征列；请使用新版 vpnflow 从 PCAP 重新生成特征", *csvPath))
	}
	if *modelFeatureSet == "trojan_post_tls_merged" && len(selectedCols) != 133 {
		fatal(fmt.Errorf("CSV %s 缺少 Trojan 后 TLS 合并特征列（期望 133=30+103 去重并集）；请使用新版 vpnflow 从 PCAP 重新生成特征", *csvPath))
	}
	var b strings.Builder
	p := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		fmt.Println(line)
		b.WriteString(line)
		b.WriteByte('\n')
	}

	p("%s vs non-%s leak-free baseline", opts.positiveLabel, opts.positiveLabel)
	p(strings.Repeat("=", 72))
	p("rows=%d, positive=%d, negative=%d", len(ds.rows), countPos(ds.y), len(ds.rows)-countPos(ds.y))
	p("training filter: packets>=%d duration>=%.2fs payload_bytes>=%d payload_pkts>=%d require_bidi=%v require_client_hello=%v require_post_tls_payload=%v require_tcp_handshake=%v",
		opts.minPackets, opts.minDuration, opts.minPayloadBytes, opts.minPayloadPkts,
		opts.requireBidi, opts.requireClientHello, opts.requirePostTLSPayload, opts.requireTCPHandshake)
	p("decision threshold: %.4f", decisionThreshold)
	p("")
	p("source distribution:")
	for _, s := range sortedSources(ds) {
		n, pos := sourceCounts(ds, s)
		p("  %-45s n=%4d pos=%3d", s, n, pos)
	}

	p("")
	p("feature policy:")
	p("  excluded: source_file, flow_key, proto, src/dst IP, src/dst port, timestamps, JA3/hash IDs, domain/ASN/GeoIP")
	p("  used feature sets are packet/flow shape only, plus a protocol-structure set without identifiers")

	p("")
	p("5-fold stratified by flow (optimistic; same source can appear in train/test)")
	p(strings.Repeat("-", 72))
	p("%-34s %6s %8s %8s %8s %8s %8s", "set", "feat", "F1", "AUC", "Prec", "Recall", "MeanP")
	for _, name := range evaluationFeatureSetNames(sets) {
		m := cvEval(ds, sets[name], 5)
		p("%-34s %6d %8.4f %8.4f %8.4f %8.4f %8.4f", name, len(sets[name]), m.f1, m.auc, m.precision, m.recall, m.meanProb)
	}

	if *externalPath != "" {
		ext, err := readDataset(*externalPath, opts)
		if err != nil {
			fatal(err)
		}
		p("")
		p("External scoring: train on main CSV, score external CSV")
		p(strings.Repeat("-", 72))
		p("external rows=%d, positive=%d, negative=%d", len(ext.rows), countPos(ext.y), len(ext.rows)-countPos(ext.y))
		p("%-34s %6s %8s %8s %8s %8s", "set", "feat", "F1", "AUC", "Prec", "Recall")
		for _, name := range evaluationFeatureSetNames(sets) {
			probs := trainPredict(ds, ext, sets[name])
			m := calcMetrics(ext.y, probs)
			p("%-34s %6d %8.4f %8.4f %8.4f %8.4f  TP=%d FP=%d TN=%d FN=%d meanP=%.4f",
				name, len(sets[name]), m.f1, m.auc, m.precision, m.recall, m.tp, m.fp, m.tn, m.fn, m.meanProb)
		}
		p("")
		p("External false positives by source using %s", *modelFeatureSet)
		p(strings.Repeat("-", 72))
		probs := trainPredict(ds, ext, selectedCols)
		printSourceFalsePositives(&b, ext, probs)
		if *predictionOut != "" {
			if err := writePredictions(*predictionOut, ext, probs, opts.positiveLabel); err != nil {
				fatal(err)
			}
		}
	}

	p("")
	p("Leave-one-source-out aggregate by feature set")
	p(strings.Repeat("-", 72))
	p("%-34s %6s %8s %8s %8s %8s %12s", "set", "feat", "F1", "AUC", "Prec", "Recall", "confusion")
	for _, name := range evaluationFeatureSetNames(sets) {
		m := looAggregateEval(ds, sets[name])
		p("%-34s %6d %8.4f %8.4f %8.4f %8.4f TP=%d FP=%d TN=%d FN=%d",
			name, len(sets[name]), m.f1, m.auc, m.precision, m.recall, m.tp, m.fp, m.tn, m.fn)
	}

	p("")
	p("Leave-one-source-out using %s (harder generalization check)", *modelFeatureSet)
	p(strings.Repeat("-", 72))
	p("%-45s %5s %7s %8s %8s %8s %8s %13s", "heldout", "n", "pos%", "F1", "AUC", "Prec", "Recall", "confusion")
	for _, s := range sortedSources(ds) {
		tr, va := splitBySource(ds, s)
		if countPos(tr.y) == 0 || countPos(tr.y) == len(tr.y) {
			p("%-45s %5d %6.1f%% %8s %8s %8s %8s %13s", s, len(va.y), pct(countPos(va.y), len(va.y)), "-", "-", "-", "-", "train onecls")
			continue
		}
		probs := trainPredict(tr, va, selectedCols)
		m := calcMetrics(va.y, probs)
		p("%-45s %5d %6.1f%% %8.4f %8.4f %8.4f %8.4f TP=%d FP=%d TN=%d FN=%d",
			s, len(va.y), pct(countPos(va.y), len(va.y)), m.f1, m.auc, m.precision, m.recall, m.tp, m.fp, m.tn, m.fn)
	}

	p("")
	p("Top coefficients, %s trained on all data", *modelFeatureSet)
	p(strings.Repeat("-", 72))
	coefRows := fitCoefficients(ds, selectedCols)
	for i, r := range coefRows {
		if i >= 25 {
			break
		}
		p("  %-34s %+9.4f", r.name, r.value)
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*outPath, []byte(b.String()), 0644); err != nil {
		fatal(err)
	}
}

func printSourceFalsePositives(b *strings.Builder, ds dataset, probs []float64) {
	printf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		fmt.Println(line)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	printf("%-45s %5s %8s %8s", "source", "n", "FP", "meanP")
	for _, s := range sortedSources(ds) {
		n, fp := 0, 0
		sum := 0.0
		for i, row := range ds.rows {
			if row["source_file"] != s {
				continue
			}
			n++
			sum += probs[i]
			if ds.y[i] == 0 && probs[i] >= decisionThreshold {
				fp++
			}
		}
		printf("%-45s %5d %8d %8.4f", s, n, fp, div(sum, float64(n)))
	}
}

func writePredictions(path string, ds dataset, probs []float64, positiveLabel string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{
		"source_file", "flow_key", "src_ip", "src_port", "dst_ip", "dst_port",
		"flow_duration", "total_packets", "positive_label", "positive_probability", "predicted_positive",
	}); err != nil {
		return err
	}
	for i, row := range ds.rows {
		p := probs[i]
		pred := "0"
		if p >= decisionThreshold {
			pred = "1"
		}
		if err := w.Write([]string{
			row["source_file"], row["flow_key"], row["src_ip"], row["src_port"],
			row["dst_ip"], row["dst_port"], row["flow_duration"], row["total_packets"],
			positiveLabel, strconv.FormatFloat(p, 'f', 8, 64), pred,
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func readDataset(path string, opts readOptions) (dataset, error) {
	f, err := os.Open(path)
	if err != nil {
		return dataset{}, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return dataset{}, err
	}
	if len(records) < 2 {
		return dataset{}, fmt.Errorf("not enough rows")
	}
	header := records[0]
	if opts.requireTCPHandshake && !containsColumn(header, "tcp_handshake_complete") {
		return dataset{}, fmt.Errorf("CSV %s 缺少 tcp_handshake_complete 列；请使用新版 vpnflow 从 PCAP 重新生成特征", path)
	}
	if opts.requirePostTLSPayload && !containsColumn(header, "post_tls_payload_ready") {
		return dataset{}, fmt.Errorf("CSV %s 缺少 post_tls_payload_ready 列；请使用新版 vpnflow 从 PCAP 重新生成特征", path)
	}
	var rows []map[string]string
	var y []int
	for _, rec := range records[1:] {
		row := make(map[string]string, len(header))
		for i, h := range header {
			if i < len(rec) {
				row[h] = rec[i]
			}
		}
		if !keepTrainingRow(row, opts) {
			continue
		}
		rows = append(rows, row)
		if row["label"] == opts.positiveLabel {
			y = append(y, 1)
		} else {
			y = append(y, 0)
		}
	}
	return dataset{header: header, rows: rows, y: y}, nil
}

func keepTrainingRow(row map[string]string, opts readOptions) bool {
	if opts.minPackets > 0 && parseInt(row["total_packets"]) < opts.minPackets {
		return false
	}
	if opts.minDuration > 0 && parseFloat(row["flow_duration"]) < opts.minDuration {
		return false
	}
	if opts.minPayloadBytes > 0 && parseInt(row["total_payload_bytes"]) < opts.minPayloadBytes {
		return false
	}
	if opts.minPayloadPkts > 0 {
		payloadPkts := parseInt(row["payload_packets"])
		if payloadPkts == 0 {
			totalPackets := parseInt(row["total_packets"])
			zeroRatio := parseFloat(row["zero_payload_ratio"])
			payloadPkts = int(math.Round(float64(totalPackets) * (1 - zeroRatio)))
		}
		if payloadPkts < opts.minPayloadPkts {
			return false
		}
	}
	if opts.requireBidi && (parseInt(row["uplink_packets"]) == 0 || parseInt(row["downlink_packets"]) == 0) {
		return false
	}
	if opts.requireClientHello && parseInt(row["outer_client_hello_present"]) != 1 {
		return false
	}
	if opts.requirePostTLSPayload && parseInt(row["post_tls_payload_ready"]) != 1 {
		return false
	}
	if opts.requireTCPHandshake && parseInt(row["tcp_handshake_complete"]) != 1 {
		return false
	}
	return true
}

func containsColumn(header []string, target string) bool {
	for _, h := range header {
		if h == target {
			return true
		}
	}
	return false
}

func featureSets(header []string) map[string][]string {
	exists := make(map[string]bool)
	for _, h := range header {
		exists[h] = true
	}
	core := []string{
		"flow_duration", "total_packets", "total_payload_bytes",
		"uplink_payload_bytes", "downlink_payload_bytes",
		"uplink_packets", "downlink_packets",
		"payload_packets", "uplink_payload_packets", "downlink_payload_packets",
		"bytes_ratio", "packet_count_ratio", "payload_packet_ratio",
		"pkts_per_second", "bytes_per_second", "payload_bytes_per_second",
		"ratio_small_100", "ratio_1514", "pkt_size_mean", "pkt_size_std", "pkt_size_cv",
		"pkt_size_entropy", "is_bimodal",
		"payload_size_mean", "payload_size_std", "payload_size_cv", "payload_size_entropy",
		"avg_payload_bytes_per_payload_pkt", "avg_uplink_payload_bytes_per_pkt", "avg_downlink_payload_bytes_per_pkt",
		"iat_mean", "iat_std", "iat_p50", "iat_p90", "burst_ratio",
		"ack_only_ratio", "zero_payload_ratio", "psh_ratio",
		"direction_switch_rate", "uplink_payload_ratio", "downlink_payload_ratio",
	}
	seq := append([]string{}, core...)
	for i := 1; i <= 10; i++ {
		seq = append(seq, fmt.Sprintf("pkt_size_%d", i))
	}
	for i := 1; i <= 10; i++ {
		seq = append(seq, fmt.Sprintf("pkt_dir_%d", i))
	}
	for i := 1; i <= 10; i++ {
		seq = append(seq, fmt.Sprintf("pkt_iat_%d", i))
	}
	seq = append(seq, "actual_pkt_count")
	for i := 1; i <= 10; i++ {
		seq = append(seq, fmt.Sprintf("payload_pkt_size_%d", i))
	}
	for i := 1; i <= 10; i++ {
		seq = append(seq, fmt.Sprintf("payload_pkt_dir_%d", i))
	}
	for i := 1; i <= 10; i++ {
		seq = append(seq, fmt.Sprintf("payload_pkt_iat_%d", i))
	}
	seq = append(seq, "actual_payload_pkt_count")

	postTLS := make([]string, 0, 30)
	for i := 1; i <= 10; i++ {
		postTLS = append(postTLS, fmt.Sprintf("post_tls_appdata_len_%d", i))
	}
	for i := 1; i <= 10; i++ {
		postTLS = append(postTLS, fmt.Sprintf("post_tls_appdata_dir_%d", i))
	}
	for i := 1; i <= 10; i++ {
		postTLS = append(postTLS, fmt.Sprintf("post_tls_appdata_iat_%d", i))
	}
	postTLSShape := make([]string, 0, len(seq))
	for _, col := range seq {
		postTLSShape = append(postTLSShape, "post_tls_shape_"+col)
	}

	proto := append([]string{}, seq...)
	proto = append(proto,
		"outer_client_hello_present", "outer_client_hello_size", "outer_tls_version",
		"outer_cipher_count", "outer_extension_count", "outer_has_grease",
	)
	for i := 1; i <= 6; i++ {
		proto = append(proto, fmt.Sprintf("outer_appdata_len_%d", i))
	}
	proto = append(proto,
		"first_uplink_appdata_size", "first_downlink_appdata_size", "first_appdata_ul_to_dl_ms",
		"inner_hello_count", "inner_offset_value", "inner_offset_valid",
	)

	filter := func(cols []string) []string {
		var out []string
		for _, c := range cols {
			if exists[c] {
				out = append(out, c)
			}
		}
		return out
	}
	seqCols := filter(postTLS)
	shapeCols := filter(postTLSShape)
	return map[string][]string{
		"shape_core":                     filter(core),
		"shape_sequence":                 filter(seq),
		"protocol_no_ids":                filter(proto),
		"trojan_post_tls_sequence":       seqCols,
		"trojan_post_tls_shape_sequence": shapeCols,
		"trojan_post_tls_merged":         uniqueConcat(seqCols, shapeCols),
	}
}

func cvEval(ds dataset, cols []string, folds int) metrics {
	idx0, idx1 := []int{}, []int{}
	for i, y := range ds.y {
		if y == 1 {
			idx1 = append(idx1, i)
		} else {
			idx0 = append(idx0, i)
		}
	}
	shuffle(idx0)
	shuffle(idx1)
	probs := make([]float64, len(ds.y))
	for f := 0; f < folds; f++ {
		test := map[int]bool{}
		for i, id := range idx0 {
			if i%folds == f {
				test[id] = true
			}
		}
		for i, id := range idx1 {
			if i%folds == f {
				test[id] = true
			}
		}
		tr, va := subsetByMask(ds, test, false), subsetByMask(ds, test, true)
		p := trainPredict(tr, va, cols)
		k := 0
		for i := range ds.y {
			if test[i] {
				probs[i] = p[k]
				k++
			}
		}
	}
	return calcMetrics(ds.y, probs)
}

func looAggregateEval(ds dataset, cols []string) metrics {
	probs := make([]float64, len(ds.y))
	filled := make([]bool, len(ds.y))
	for _, s := range sortedSources(ds) {
		tr, va := splitBySource(ds, s)
		if countPos(tr.y) == 0 || countPos(tr.y) == len(tr.y) {
			continue
		}
		p := trainPredict(tr, va, cols)
		k := 0
		for i, row := range ds.rows {
			if row["source_file"] == s {
				probs[i] = p[k]
				filled[i] = true
				k++
			}
		}
	}
	var y2 []int
	var p2 []float64
	for i := range ds.y {
		if filled[i] {
			y2 = append(y2, ds.y[i])
			p2 = append(p2, probs[i])
		}
	}
	return calcMetrics(y2, p2)
}

func trainPredict(tr, va dataset, cols []string) []float64 {
	xtr, means, stds := matrix(tr, cols, nil, nil)
	xva, _, _ := matrix(va, cols, means, stds)
	w := trainLogReg(xtr, tr.y)
	return predictLogReg(xva, w)
}

func matrix(ds dataset, cols []string, means, stds []float64) ([][]float64, []float64, []float64) {
	x := make([][]float64, len(ds.rows))
	for i, row := range ds.rows {
		x[i] = make([]float64, len(cols))
		for j, c := range cols {
			x[i][j] = parseFloat(row[c])
		}
	}
	if means == nil {
		means = make([]float64, len(cols))
		stds = make([]float64, len(cols))
		for j := range cols {
			for i := range x {
				means[j] += x[i][j]
			}
			means[j] /= math.Max(float64(len(x)), 1)
			for i := range x {
				d := x[i][j] - means[j]
				stds[j] += d * d
			}
			stds[j] = math.Sqrt(stds[j]/math.Max(float64(len(x)), 1) + 1e-12)
		}
	}
	for i := range x {
		for j := range cols {
			x[i][j] = (x[i][j] - means[j]) / stds[j]
		}
	}
	return x, means, stds
}

func trainLogReg(x [][]float64, y []int) []float64 {
	if len(x) == 0 {
		return nil
	}
	d := len(x[0]) + 1
	w := make([]float64, d)
	pos := countPos(y)
	neg := len(y) - pos
	posWeight := float64(len(y)) / math.Max(float64(2*pos), 1)
	negWeight := float64(len(y)) / math.Max(float64(2*neg), 1)
	lr := 0.05
	l2 := 0.0005
	for it := 0; it < 1200; it++ {
		g := make([]float64, d)
		for i := range x {
			z := w[0]
			for j, v := range x[i] {
				z += w[j+1] * v
			}
			p := sigmoid(z)
			wt := negWeight
			if y[i] == 1 {
				wt = posWeight
			}
			err := (p - float64(y[i])) * wt
			g[0] += err
			for j, v := range x[i] {
				g[j+1] += err * v
			}
		}
		scale := 1 / math.Max(float64(len(x)), 1)
		w[0] -= lr * g[0] * scale
		for j := 1; j < d; j++ {
			w[j] -= lr * (g[j]*scale + l2*w[j])
		}
	}
	return w
}

func predictLogReg(x [][]float64, w []float64) []float64 {
	out := make([]float64, len(x))
	for i := range x {
		z := w[0]
		for j, v := range x[i] {
			z += w[j+1] * v
		}
		out[i] = sigmoid(z)
	}
	return out
}

func sigmoid(x float64) float64 {
	if x > 35 {
		return 1
	}
	if x < -35 {
		return 0
	}
	return 1 / (1 + math.Exp(-x))
}

func calcMetrics(y []int, probs []float64) metrics {
	m := metrics{n: len(y), pos: countPos(y)}
	for i, p := range probs {
		m.meanProb += p
		pred := 0
		if p >= decisionThreshold {
			pred = 1
		}
		switch {
		case pred == 1 && y[i] == 1:
			m.tp++
		case pred == 1 && y[i] == 0:
			m.fp++
		case pred == 0 && y[i] == 0:
			m.tn++
		case pred == 0 && y[i] == 1:
			m.fn++
		}
	}
	if len(probs) > 0 {
		m.meanProb /= float64(len(probs))
	}
	m.precision = div(float64(m.tp), float64(m.tp+m.fp))
	m.recall = div(float64(m.tp), float64(m.tp+m.fn))
	m.f1 = div(2*m.precision*m.recall, m.precision+m.recall)
	m.auc = auc(y, probs)
	return m
}

func auc(y []int, probs []float64) float64 {
	type pair struct {
		y int
		p float64
	}
	ps := make([]pair, len(y))
	pos, neg := 0, 0
	for i := range y {
		ps[i] = pair{y: y[i], p: probs[i]}
		if y[i] == 1 {
			pos++
		} else {
			neg++
		}
	}
	if pos == 0 || neg == 0 {
		return 0
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].p < ps[j].p })
	rankSum := 0.0
	for i := 0; i < len(ps); {
		j := i + 1
		for j < len(ps) && ps[j].p == ps[i].p {
			j++
		}
		avgRank := float64(i+j+1) / 2
		for k := i; k < j; k++ {
			if ps[k].y == 1 {
				rankSum += avgRank
			}
		}
		i = j
	}
	return (rankSum - float64(pos*(pos+1))/2) / float64(pos*neg)
}

type coefRow struct {
	name  string
	value float64
}

func fitCoefficients(ds dataset, cols []string) []coefRow {
	x, _, _ := matrix(ds, cols, nil, nil)
	w := trainLogReg(x, ds.y)
	var rows []coefRow
	for i, c := range cols {
		rows = append(rows, coefRow{name: c, value: w[i+1]})
	}
	sort.Slice(rows, func(i, j int) bool {
		return math.Abs(rows[i].value) > math.Abs(rows[j].value)
	})
	return rows
}

func splitBySource(ds dataset, held string) (dataset, dataset) {
	mask := map[int]bool{}
	for i, row := range ds.rows {
		if row["source_file"] == held {
			mask[i] = true
		}
	}
	return subsetByMask(ds, mask, false), subsetByMask(ds, mask, true)
}

func subsetByMask(ds dataset, mask map[int]bool, want bool) dataset {
	out := dataset{header: ds.header}
	for i := range ds.rows {
		if mask[i] == want {
			out.rows = append(out.rows, ds.rows[i])
			out.y = append(out.y, ds.y[i])
		}
	}
	return out
}

func sortedSources(ds dataset) []string {
	set := map[string]bool{}
	for _, r := range ds.rows {
		set[r["source_file"]] = true
	}
	var out []string
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sourceCounts(ds dataset, source string) (int, int) {
	n, pos := 0, 0
	for i, r := range ds.rows {
		if r["source_file"] == source {
			n++
			pos += ds.y[i]
		}
	}
	return n, pos
}

func parseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

func parseInt(s string) int {
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

func countPos(y []int) int {
	n := 0
	for _, v := range y {
		n += v
	}
	return n
}

func div(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func pct(a, b int) float64 {
	return 100 * div(float64(a), float64(b))
}

func shuffle(xs []int) {
	var seed uint64 = 0x9e3779b97f4a7c15
	for i := len(xs) - 1; i > 0; i-- {
		seed = seed*6364136223846793005 + 1
		j := int(seed % uint64(i+1))
		xs[i], xs[j] = xs[j], xs[i]
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
