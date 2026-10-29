package money

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	MicrosPerCredit Micros = tenThousandths
	tenThousandths         = 10_000
)

var creditPlaces = len(strconv.Itoa(tenThousandths)) - 1

var ErrInvalidCredits = errors.New("billing: credits must be 0 or more with at most four decimal places")

type Credits struct{ micros Micros }

func (m Micros) Credits() Credits { return Credits{m} }

func (c Credits) String() string {
	abs, sign := uint64(c.micros), ""
	if c.micros < 0 {
		abs, sign = -abs, "-"
	}
	per := uint64(MicrosPerCredit)
	whole := sign + strconv.FormatUint(abs/per, 10)
	if abs%per == 0 {
		return whole
	}
	return whole + "." + strings.TrimRight(fmt.Sprintf("%0*d", creditPlaces, abs%per), "0")
}

func (c Credits) MarshalJSON() ([]byte, error) { return []byte(c.String()), nil }

func ParseCredits(text string) (Micros, error) {
	n, ok := parseTenThousandths(text)
	if !ok {
		return 0, ErrInvalidCredits
	}
	return Micros(n), nil
}

func parseTenThousandths(text string) (int64, bool) {
	whole, fraction, dotted := strings.Cut(text, ".")
	if !decimalDigits(whole) || dotted && !decimalDigits(fraction) || len(fraction) > creditPlaces {
		return 0, false
	}
	part, _ := strconv.ParseInt(fraction+strings.Repeat("0", creditPlaces-len(fraction)), 10, 64)
	units, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || units > (math.MaxInt64-part)/tenThousandths {
		return 0, false
	}
	return units*tenThousandths + part, true
}

func decimalDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}
