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

var labels = []string{"clean", "shadowsocks", "trojan", "vmess_vless"}

type dataset struct {
	header []string
	rows   []map[string]string
	y      []int
}

type readOptions struct {
	minPackets      int
	minDuration     float64
	minPayloadBytes int
	minPayloadPkts  int
	requireBidi     bool
}

type multiMetrics struct {
	n         int
	accuracy  float64
	macroF1   float64
	precision []float64
	recall    []float64
	f1        []float64
	conf      [][]int
}

func main() {
	csvPath := flag.String("csv", filepath.Join("out", "ss_clean_hardneg.csv"), "feature CSV")
	outPath := flag.String("out", filepath.Join("out", "multi_eval_report.txt"), "report path")
	minPackets := flag.Int("min-train-packets", 20, "training-side minimum total packets")
	minDuration := flag.Float64("min-train-duration", 1.0, "training-side minimum flow duration seconds")
	minPayloadBytes := flag.Int("min-train-payload-bytes", 1000, "training-side minimum total payload bytes")
	minPayloadPkts := flag.Int("min-train-payload-pkts", 3, "training-side minimum packets with payload, estimated from zero_payload_ratio")
	requireBidi := flag.Bool("train-require-bidi", true, "training-side require bidirectional packet counts")
	flag.Parse()

	opts := readOptions{
		minPackets:      *minPackets,
		minDuration:     *minDuration,
		minPayloadBytes: *minPayloadBytes,
		minPayloadPkts:  *minPayloadPkts,
		requireBidi:     *requireBidi,
	}

	ds, err := readDataset(*csvPath, opts)
	if err != nil {
		fatal(err)
	}
	sets := featureSets(ds.header)

	var b strings.Builder
	p := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		fmt.Println(line)
		b.WriteString(line)
		b.WriteByte('\n')
	}

	p("VPN traffic multiclass leak-free baseline")
	p(strings.Repeat("=", 78))
	p("rows=%d", len(ds.rows))
	p("training filter: packets>=%d duration>=%.2fs payload_bytes>=%d payload_pkts>=%d require_bidi=%v",
		opts.minPackets, opts.minDuration, opts.minPayloadBytes, opts.minPayloadPkts, opts.requireBidi)
	p("")
	p("label distribution:")
	for i, name := range labels {
		p("  %-12s n=%4d", name, countClass(ds.y, i))
	}
	p("")
	p("source distribution:")
	for _, s := range sortedSources(ds) {
		counts := sourceClassCounts(ds, s)
		p("  %-45s clean=%3d ss=%3d trojan=%3d vless=%3d",
			s, counts[0], counts[1], counts[2], counts[3])
	}
	p("")
	p("feature policy:")
	p("  excluded: source_file, flow_key, proto, src/dst IP, src/dst port, timestamps, JA3/hash IDs, domain/ASN/GeoIP")

	p("")
	p("5-fold stratified by class (optimistic; same source can appear in train/test)")
	p(strings.Repeat("-", 78))
	p("%-22s %6s %9s %9s", "set", "feat", "accuracy", "macro_f1")
	for _, name := range []string{"shape_core", "shape_sequence", "protocol_no_ids"} {
		m := cvEval(ds, sets[name], 5)
		p("%-22s %6d %9.4f %9.4f", name, len(sets[name]), m.accuracy, m.macroF1)
	}

	p("")
	p("Leave-one-source-out aggregate by feature set")
	p(strings.Repeat("-", 78))
	p("%-22s %6s %9s %9s", "set", "feat", "accuracy", "macro_f1")
	for _, name := range []string{"shape_core", "shape_sequence", "protocol_no_ids"} {
		m := looAggregateEval(ds, sets[name])
		p("%-22s %6d %9.4f %9.4f", name, len(sets[name]), m.accuracy, m.macroF1)
	}

	p("")
	p("Leave-one-source-out detail using protocol_no_ids")
	p(strings.Repeat("-", 78))
	p("%-45s %5s %9s %9s", "heldout", "n", "accuracy", "macro_f1")
	for _, s := range sortedSources(ds) {
		tr, va := splitBySource(ds, s)
		if !hasAllTrainClasses(tr.y) {
			p("%-45s %5d %9s %9s", s, len(va.y), "-", "train lacks class")
			continue
		}
		probs := trainPredict(tr, va, sets["protocol_no_ids"])
		m := calcMultiMetrics(va.y, probs)
		p("%-45s %5d %9.4f %9.4f", s, len(va.y), m.accuracy, m.macroF1)
	}

	p("")
	p("Confusion matrix: leave-one-source-out protocol_no_ids")
	p(strings.Repeat("-", 78))
	m := looAggregateEval(ds, sets["protocol_no_ids"])
	printConfusion(&b, m)

	p("")
	p("Per-class metrics: leave-one-source-out protocol_no_ids")
	p(strings.Repeat("-", 78))
	p("%-12s %9s %9s %9s", "class", "precision", "recall", "f1")
	for i, name := range labels {
		p("%-12s %9.4f %9.4f %9.4f", name, m.precision[i], m.recall[i], m.f1[i])
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*outPath, []byte(b.String()), 0644); err != nil {
		fatal(err)
	}
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
	labelToID := map[string]int{}
	for i, l := range labels {
		labelToID[l] = i
	}
	header := records[0]
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
		id, ok := labelToID[row["label"]]
		if !ok {
			continue
		}
		rows = append(rows, row)
		y = append(y, id)
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
	return true
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
	return map[string][]string{
		"shape_core":      filter(core),
		"shape_sequence":  filter(seq),
		"protocol_no_ids": filter(proto),
	}
}

func cvEval(ds dataset, cols []string, folds int) multiMetrics {
	byClass := make([][]int, len(labels))
	for i, y := range ds.y {
		byClass[y] = append(byClass[y], i)
	}
	for i := range byClass {
		shuffle(byClass[i])
	}
	probs := make([][]float64, len(ds.y))
	for f := 0; f < folds; f++ {
		test := map[int]bool{}
		for _, ids := range byClass {
			for i, id := range ids {
				if i%folds == f {
					test[id] = true
				}
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
	return calcMultiMetrics(ds.y, probs)
}

func looAggregateEval(ds dataset, cols []string) multiMetrics {
	probs := make([][]float64, len(ds.y))
	filled := make([]bool, len(ds.y))
	for _, s := range sortedSources(ds) {
		tr, va := splitBySource(ds, s)
		if !hasAllTrainClasses(tr.y) {
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
	var p2 [][]float64
	for i := range ds.y {
		if filled[i] {
			y2 = append(y2, ds.y[i])
			p2 = append(p2, probs[i])
		}
	}
	return calcMultiMetrics(y2, p2)
}

func trainPredict(tr, va dataset, cols []string) [][]float64 {
	xtr, means, stds := matrix(tr, cols, nil, nil)
	xva, _, _ := matrix(va, cols, means, stds)
	w := trainSoftmax(xtr, tr.y, len(labels))
	return predictSoftmax(xva, w, len(labels))
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

func trainSoftmax(x [][]float64, y []int, classes int) [][]float64 {
	if len(x) == 0 {
		return nil
	}
	d := len(x[0]) + 1
	w := make([][]float64, classes)
	for k := range w {
		w[k] = make([]float64, d)
	}
	counts := make([]int, classes)
	for _, yy := range y {
		counts[yy]++
	}
	classWeight := make([]float64, classes)
	for k := range classWeight {
		classWeight[k] = float64(len(y)) / math.Max(float64(classes*counts[k]), 1)
	}
	lr := 0.04
	l2 := 0.0005
	for it := 0; it < 1500; it++ {
		g := make([][]float64, classes)
		for k := range g {
			g[k] = make([]float64, d)
		}
		for i := range x {
			p := softmaxLogits(x[i], w)
			wt := classWeight[y[i]]
			for k := 0; k < classes; k++ {
				target := 0.0
				if y[i] == k {
					target = 1
				}
				err := (p[k] - target) * wt
				g[k][0] += err
				for j, v := range x[i] {
					g[k][j+1] += err * v
				}
			}
		}
		scale := 1 / math.Max(float64(len(x)), 1)
		for k := 0; k < classes; k++ {
			w[k][0] -= lr * g[k][0] * scale
			for j := 1; j < d; j++ {
				w[k][j] -= lr * (g[k][j]*scale + l2*w[k][j])
			}
		}
	}
	return w
}

func predictSoftmax(x [][]float64, w [][]float64, classes int) [][]float64 {
	out := make([][]float64, len(x))
	for i := range x {
		out[i] = softmaxLogits(x[i], w)
	}
	return out
}

func softmaxLogits(x []float64, w [][]float64) []float64 {
	logits := make([]float64, len(w))
	maxv := math.Inf(-1)
	for k := range w {
		z := w[k][0]
		for j, v := range x {
			z += w[k][j+1] * v
		}
		logits[k] = z
		if z > maxv {
			maxv = z
		}
	}
	sum := 0.0
	for k := range logits {
		logits[k] = math.Exp(logits[k] - maxv)
		sum += logits[k]
	}
	for k := range logits {
		logits[k] /= sum
	}
	return logits
}

func calcMultiMetrics(y []int, probs [][]float64) multiMetrics {
	classes := len(labels)
	m := multiMetrics{
		n:         len(y),
		precision: make([]float64, classes),
		recall:    make([]float64, classes),
		f1:        make([]float64, classes),
		conf:      make([][]int, classes),
	}
	for i := range m.conf {
		m.conf[i] = make([]int, classes)
	}
	correct := 0
	for i, yy := range y {
		pred := argmax(probs[i])
		m.conf[yy][pred]++
		if pred == yy {
			correct++
		}
	}
	m.accuracy = div(float64(correct), float64(len(y)))
	for k := 0; k < classes; k++ {
		tp := m.conf[k][k]
		predicted, actual := 0, 0
		for i := 0; i < classes; i++ {
			predicted += m.conf[i][k]
			actual += m.conf[k][i]
		}
		m.precision[k] = div(float64(tp), float64(predicted))
		m.recall[k] = div(float64(tp), float64(actual))
		m.f1[k] = div(2*m.precision[k]*m.recall[k], m.precision[k]+m.recall[k])
		m.macroF1 += m.f1[k]
	}
	m.macroF1 /= float64(classes)
	return m
}

func printConfusion(b *strings.Builder, m multiMetrics) {
	printf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		fmt.Println(line)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	printf("%-12s %8s %8s %8s %10s", "true\\pred", labels[0], labels[1], labels[2], labels[3])
	for i, name := range labels {
		printf("%-12s %8d %8d %8d %10d", name, m.conf[i][0], m.conf[i][1], m.conf[i][2], m.conf[i][3])
	}
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

func sourceClassCounts(ds dataset, source string) []int {
	counts := make([]int, len(labels))
	for i, r := range ds.rows {
		if r["source_file"] == source {
			counts[ds.y[i]]++
		}
	}
	return counts
}

func hasAllTrainClasses(y []int) bool {
	for k := range labels {
		if countClass(y, k) == 0 {
			return false
		}
	}
	return true
}

func countClass(y []int, k int) int {
	n := 0
	for _, v := range y {
		if v == k {
			n++
		}
	}
	return n
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

func argmax(xs []float64) int {
	best := 0
	for i := 1; i < len(xs); i++ {
		if xs[i] > xs[best] {
			best = i
		}
	}
	return best
}

func div(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
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
