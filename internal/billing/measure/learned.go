package measure

import (
	"math"

	"morse/backend/internal/enum"
)

type Figure uint8

const (
	FigurePromptOverhead Figure = iota
	FigureCompletionOffset
	FigureThinkingRate
	FigureReplyBytesPerToken
)

var figureNames = enum.Names[Figure]{
	FigurePromptOverhead:     "prompt_overhead",
	FigureCompletionOffset:   "completion_offset",
	FigureThinkingRate:       "thinking_rate",
	FigureReplyBytesPerToken: "reply_bytes_per_token",
}

func (f Figure) String() string { return figureNames.String(f) }

func (f Figure) MarshalText() ([]byte, error) { return figureNames.MarshalText(f) }

func (f *Figure) UnmarshalText(text []byte) error { return figureNames.UnmarshalText(f, text) }

func ParseFigure(name string) (Figure, bool) { return figureNames.Parse(name) }

type Sample struct {
	Route  string
	Figure Figure
	Value  float64
}

type LearnedFigure struct {
	Route    string
	Figure   Figure
	Median   float64
	P10      float64
	Accounts int
}

const MinLearningAccounts = 5

type learnedKey struct {
	route  string
	figure Figure
}

type Learned struct {
	figures map[learnedKey]LearnedFigure
}

func NewLearned(figures []LearnedFigure) Learned {
	l := Learned{figures: make(map[learnedKey]LearnedFigure, len(figures))}
	for _, f := range figures {
		l.figures[learnedKey{f.Route, f.Figure}] = f
	}
	return l
}

func (l Learned) figure(route string, f Figure) (LearnedFigure, bool) {
	fig, ok := l.figures[learnedKey{route, f}]
	if !ok || fig.Accounts < MinLearningAccounts {
		return LearnedFigure{}, false
	}
	return fig, true
}

func (l Learned) Calibration(route string, f Figure) (int, bool) {
	fig, ok := l.figure(route, f)
	return int(math.Round(fig.Median)), ok
}

type RouteFigures struct {
	ThinkingRate                     int
	ReplyBytesPerToken               float64
	PromptOverhead, CompletionOffset Calibration
}

type Calibration struct {
	Offset  int
	Learned bool
}

func (l Learned) Figures(route string, t ThinkingTerms) RouteFigures {
	f := RouteFigures{ThinkingRate: l.ThinkingRate(route, t), ReplyBytesPerToken: l.ReplyBytesPerToken(route)}
	f.PromptOverhead.Offset, f.PromptOverhead.Learned = l.Calibration(route, FigurePromptOverhead)
	f.CompletionOffset.Offset, f.CompletionOffset.Learned = l.Calibration(route, FigureCompletionOffset)
	return f
}

type ThinkingTerms struct {
	Seed, DecodeMax int
}

func (l Learned) ThinkingRate(route string, t ThinkingTerms) int {
	rate := t.Seed
	if learned, ok := l.figure(route, FigureThinkingRate); ok {
		rate = min(max(int(math.Round(learned.P10)), t.Seed/2), t.Seed*2)
	}
	return min(rate, t.DecodeMax)
}

const (
	unlearnedReplyBytesPerToken = 4
	minReplyBytesPerToken       = 1
	maxReplyBytesPerToken       = 8
)

func (l Learned) ReplyBytesPerToken(route string) float64 {
	learned, ok := l.figure(route, FigureReplyBytesPerToken)
	if !ok {
		return unlearnedReplyBytesPerToken
	}
	return min(max(learned.Median, minReplyBytesPerToken), maxReplyBytesPerToken)
}
