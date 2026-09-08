package main

import (
	"reflect"
	"testing"

	"vpnflow/pkg/model"
)

func TestUniqueConcatDedupsPreservingOrder(t *testing.T) {
	got := uniqueConcat([]string{"a", "b", "a"}, []string{"b", "c"}, []string{"c", "d"})
	want := []string{"a", "b", "c", "d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("uniqueConcat=%v, want %v", got, want)
	}
}

func TestFeatureSetsMergedIsDedupedUnion(t *testing.T) {
	sets := featureSets(model.CSVHeader())
	seq := sets["trojan_post_tls_sequence"]
	shape := sets["trojan_post_tls_shape_sequence"]
	merged := sets["trojan_post_tls_merged"]
	if len(seq) != 30 {
		t.Fatalf("sequence feat=%d, want 30", len(seq))
	}
	if len(shape) != 103 {
		t.Fatalf("shape feat=%d, want 103", len(shape))
	}
	if len(merged) != 133 {
		t.Fatalf("merged feat=%d, want 133", len(merged))
	}
	if !reflect.DeepEqual(merged, uniqueConcat(seq, shape)) {
		t.Fatal("merged is not the deduped union of sequence and shape")
	}
	seen := map[string]int{}
	for _, c := range merged {
		seen[c]++
		if seen[c] > 1 {
			t.Fatalf("duplicate column in merged: %s", c)
		}
	}
}
