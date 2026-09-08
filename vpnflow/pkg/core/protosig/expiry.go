package protosig

import (
	"time"

	"vpnflow/pkg/model"
)

type flowExpiryItem struct {
	key        model.FlowKey
	at         time.Time
	generation uint64
}

type flowExpiryHeap []flowExpiryItem

func (h flowExpiryHeap) Len() int           { return len(h) }
func (h flowExpiryHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h flowExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *flowExpiryHeap) Push(x any)        { *h = append(*h, x.(flowExpiryItem)) }
func (h *flowExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

type sessionExpiryItem struct {
	id         string
	at         time.Time
	generation uint64
}

type sessionExpiryHeap []sessionExpiryItem

func (h sessionExpiryHeap) Len() int           { return len(h) }
func (h sessionExpiryHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h sessionExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *sessionExpiryHeap) Push(x any)        { *h = append(*h, x.(sessionExpiryItem)) }
func (h *sessionExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}
