package tokenizer

import (
	"bytes"
	"compress/gzip"
	"embed"
	"fmt"
	"io"
	"sync"
)

//go:embed data/*.gz
var files embed.FS

type source struct {
	file    string
	load    func([]byte) (*Tokenizer, error)
	pattern string
}

// Sources, pinned by the sha256 of each decompressed file in tokenizer_test.go:
//   - glm-5: zai-org/GLM-5.3-Flash@eb9eb208 tokenizer.json, the same file GLM-5.3 and GLM-5.2 serve.
//   - deepseek-v4: deepseek-ai/DeepSeek-V4.1-Flash@2cba9e42 tokenizer.json. DeepSeek-V4-Pro-0813's
//     differs only in one added token, <｜System｜>.
//   - kimi-k3: moonshotai/Kimi-K3@f831ab66 tiktoken.model with the pattern from its tokenization_kimi.py.
//   - o200k: tiktoken's o200k_base.
var sources = map[string]source{
	"glm-5":       {file: "data/glm-5.json.gz", load: loadHF},
	"deepseek-v4": {file: "data/deepseek-v4.json.gz", load: loadHF},
	"kimi-k3":     {file: "data/kimi-k3.tiktoken.gz", pattern: kimiPattern},
	"o200k":       {file: "data/o200k_base.tiktoken.gz", pattern: o200kPattern},
}

const o200kPattern = `[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n/]*|\s*[\r\n]+|\s+(?!\S)|\s+`

var loaded sync.Map

type once struct {
	sync.Once
	t   *Tokenizer
	err error
}

func Load(name string) (*Tokenizer, error) {
	src, ok := sources[name]
	if !ok {
		return nil, fmt.Errorf("tokenizer %q, which the proxy does not embed", name)
	}
	v, _ := loaded.LoadOrStore(name, &once{})
	o := v.(*once)
	o.Do(func() {
		if o.t, o.err = src.open(); o.err != nil {
			o.err = fmt.Errorf("tokenizer %q: %w", name, o.err)
		}
	})
	return o.t, o.err
}

func (s source) open() (*Tokenizer, error) {
	data, err := decompressed(s.file)
	if err != nil {
		return nil, err
	}
	if s.load != nil {
		return s.load(data)
	}
	return loadTiktoken(data, s.pattern)
}

func decompressed(file string) ([]byte, error) {
	raw, err := files.ReadFile(file)
	if err != nil {
		return nil, err
	}
	r, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
