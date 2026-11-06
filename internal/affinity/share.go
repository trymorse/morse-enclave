package affinity

// Share is a share of conversations in basis points, 0 to WholeShare.
type Share uint16

const (
	WholeShare    Share = 10_000
	DefaultSpread Share = 1_000
	DefaultCanary Share = 100
)

func (s Share) Valid() bool { return s <= WholeShare }
