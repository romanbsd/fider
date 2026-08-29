package metrics

import "github.com/prometheus/client_golang/prometheus"

// AppCheckVerifications records low-cardinality Firebase App Check outcomes.
// Tokens, app IDs, tenant IDs, and other caller-controlled values are
// deliberately excluded from labels.
var AppCheckVerifications = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "fider_app_check_verifications_total",
		Help: "Number of Firebase App Check verification attempts.",
	},
	[]string{"mode", "result"},
)

func init() {
	prometheus.MustRegister(AppCheckVerifications)
}
