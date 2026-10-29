package measure

import "morse/backend/internal/enum"

type UsageSource uint8

const (
	UsageUnknown UsageSource = iota
	UsageReported
	UsageEstimated
	UsageClient
	UsageHold
	UsageNone
	UsageMetered
	UsageCounted
	UsageCalibrated
)

var usageSourceNames = enum.Names[UsageSource]{
	UsageReported:   "reported",
	UsageEstimated:  "estimated",
	UsageClient:     "client",
	UsageHold:       "hold",
	UsageNone:       "none",
	UsageMetered:    "metered",
	UsageCounted:    "counted",
	UsageCalibrated: "calibrated",
}

func ParseUsageSource(name string) (UsageSource, bool) { return usageSourceNames.Parse(name) }

func KnownUsageSources() []UsageSource { return usageSourceNames.Values() }

func (s UsageSource) Known() bool { return usageSourceNames.Valid(s) }

func (s UsageSource) String() string {
	if s == UsageUnknown {
		return "unknown"
	}
	return usageSourceNames.String(s)
}
