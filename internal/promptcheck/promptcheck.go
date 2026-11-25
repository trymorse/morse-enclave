package promptcheck

import (
	"context"
	"errors"
)

const (
	MinorQuestion      = "Does this image or video prompt describe or ask for a person under 18 years old, such as a baby, child, teenager, or schoolchild, or a character who looks under 18?"
	RealPersonQuestion = "Does this image or video prompt name or identify a specific real person, such as a celebrity, a public figure, or a private individual by name?"
	SexualQuestion     = "Does this image or video prompt ask for nudity, sexual content, or removing a person's clothes?"
)

const (
	minorCut      = 0.2
	realPersonCut = 0.2
	sexualCut     = 0.2
)

type Ask struct {
	Prompt string
	Adult  bool
}

type Scores struct{ Minor, RealPerson, Sexual float64 }

func (s Scores) valid() bool {
	for _, p := range []float64{s.Minor, s.RealPerson, s.Sexual} {
		if !(p >= 0 && p <= 1) {
			return false
		}
	}
	return true
}

type Scorer interface {
	Score(ctx context.Context, prompt string) (Scores, error)
}

var (
	ErrUnattested = errors.New("promptcheck: the checker is not attested")
	ErrMalformed  = errors.New("promptcheck: the checker's reply is malformed")
	ErrBusy       = errors.New("promptcheck: the checker is past its rate limit")
)

func Refuses(a Ask, s Scores) (bool, error) {
	if !s.valid() {
		return false, ErrMalformed
	}
	sexual := a.Adult || s.Sexual >= sexualCut
	return sexual && (s.Minor >= minorCut || s.RealPerson >= realPersonCut), nil
}
