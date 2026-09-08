package main

// uniqueConcat 按出现顺序拼接多个特征列，去掉重复列名。
func uniqueConcat(sets ...[]string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0)
	for _, cols := range sets {
		for _, c := range cols {
			if seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func evaluationFeatureSetNames(sets map[string][]string) []string {
	order := []string{
		"shape_core",
		"shape_sequence",
		"protocol_no_ids",
		"trojan_post_tls_sequence",
		"trojan_post_tls_shape_sequence",
		"trojan_post_tls_merged",
	}
	out := make([]string, 0, len(order))
	for _, name := range order {
		if len(sets[name]) > 0 {
			out = append(out, name)
		}
	}
	return out
}
