package worker

import (
	"cmp"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/chat"
)

type keyBill struct {
	price money.Price
	veil  money.Micros
}

// why: the Veil's scan has run by the time an attempt starts, and the ledger charges it inside the chat's cost, so usage.cost
// carries it too.
func (o *openedChat) usageCost(g ChatGrant) *keyBill {
	if !o.dialect.Native() || o.protocol.scheme != nil || g.KeyPrice == nil {
		return nil
	}
	bill := &keyBill{price: *g.KeyPrice}
	if v := o.veilMeasure; v != nil && v.Failed != VeilSelfCheck {
		bill.veil = g.VeilPrice.Of(v.Calls, v.Tokens)
	}
	return bill
}

func costed(c chat.Chunk, bill *keyBill, reported chat.Usage, unanswered bool) chat.Chunk {
	if bill == nil {
		return c
	}
	cost := bill.price.Bill(measure.Measurement{Tokens: reported.Normalized(), Unanswered: unanswered}).Cost + bill.veil
	return c.AddToUsage("cost", []byte(cost.DollarFigure()))
}

func (s *sseWriter) emitHoldingUsage(c chat.Chunk) error {
	if s.price != nil && c.CarriesUsage() {
		s.heldUsage = &c
		return nil
	}
	return s.emit(c)
}

func (s *sseWriter) releaseUsage(reported chat.Usage, err error) error {
	if s.heldUsage == nil {
		return err
	}
	c := costed(*s.heldUsage, s.price, reported, unanswered(s.finish, s.sent))
	s.heldUsage = nil
	return cmp.Or(err, s.emit(c))
}
