package money

import (
	"fmt"
	"strings"
)

func (m Micros) DollarFigure() string {
	sign := ""
	if m < 0 {
		sign, m = "-", -m
	}
	whole, fraction := m/1_000_000, m%1_000_000
	if fraction == 0 {
		return fmt.Sprintf("%s%d", sign, whole)
	}
	return fmt.Sprintf("%s%d.%s", sign, whole, strings.TrimRight(fmt.Sprintf("%06d", fraction), "0"))
}
