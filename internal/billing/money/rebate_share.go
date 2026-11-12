package money

// RebateShare is the part of a charge's margin that the hourly rebate returns to the account, in basis points.
// Each model publishes its own, and the charge keeps the one in force when it opened.
type RebateShare int64

const (
	DefaultRebateShare RebateShare = 5_000
	WholeMargin        RebateShare = 10_000
)

func (s RebateShare) Valid() bool { return s >= 0 && s <= WholeMargin }
