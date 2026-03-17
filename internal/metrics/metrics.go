// Package metrics provides Prometheus instrumentation for AEGIS.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aegis",
			Name:      "requests_total",
			Help:      "Total requests processed by AEGIS proxy.",
		},
		[]string{"verdict"},
	)

	ClassificationDistribution = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aegis",
			Name:      "classification_total",
			Help:      "Layer 1 classification distribution.",
		},
		[]string{"class"},
	)

	Layer1Latency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "aegis",
			Subsystem: "layer1",
			Name:      "latency_seconds",
			Help:      "Layer 1 (classifier) latency in seconds.",
			Buckets:   []float64{.001, .0025, .005, .01, .025, .05, .1},
		},
	)

	Layer2Latency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "aegis",
			Subsystem: "layer2",
			Name:      "latency_seconds",
			Help:      "Layer 2 (auditor) latency in seconds.",
			Buckets:   []float64{.1, .25, .5, 1, 2.5, 5, 10},
		},
	)

	Layer3Latency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "aegis",
			Subsystem: "layer3",
			Name:      "latency_seconds",
			Help:      "Layer 3 (sanitizer) latency in seconds.",
			Buckets:   []float64{.001, .0025, .005, .01, .025, .05, .1},
		},
	)

	TotalLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "aegis",
			Name:      "request_latency_seconds",
			Help:      "Total end-to-end request latency in seconds.",
			Buckets:   []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
	)

	PHIDetections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aegis",
			Subsystem: "layer3",
			Name:      "phi_detections_total",
			Help:      "PHI detections by type.",
		},
		[]string{"phi_type", "channel"},
	)

	AuditorErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "aegis",
			Subsystem: "layer2",
			Name:      "errors_total",
			Help:      "Layer 2 auditor errors (LLM call failures, parse failures).",
		},
	)
)
