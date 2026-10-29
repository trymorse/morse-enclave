package money

type Micros int64

func (m Micros) Covers(hold Micros) bool { return m >= hold }
