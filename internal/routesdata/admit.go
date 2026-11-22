package routesdata

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"morse/backend/internal/pinsig"
	"morse/backend/internal/sigstore/rekorv2"
)

const (
	MaxAge       = 7 * 24 * time.Hour
	MaxStatement = 128 << 10
	MaxFile      = 4 << 20
)

var (
	ErrSize = errors.New("routesdata: an offered file is over its size limit")
	ErrLoad = errors.New("routesdata: the worker's loaders refuse the routes file")
)

type Trust struct {
	Root      pinsig.TrustRoot
	Identity  pinsig.Identity
	Witnesses rekorv2.WitnessPolicy
}

type Image struct {
	Environment string
	Boot        []byte
	Floor       uint64
	MaxAge      time.Duration
	Trust       Trust
	Load        func(file []byte) error
}

type Offer struct {
	Statement []byte
	Bundle    []byte
	File      []byte
}

type Admitted struct {
	Sequence        uint64
	StatementSHA256 string
	FileSHA256      string
	Signed          time.Time
	File            []byte
}

func (i Image) Admit(o Offer, now time.Time) (Admitted, error) {
	if len(o.Statement) > MaxStatement || len(o.Bundle) > MaxStatement || len(o.File) > MaxFile {
		return Admitted{}, fmt.Errorf("%w: statement %d, bundle %d and file %d bytes, over %d, %d and %d", ErrSize, len(o.Statement), len(o.Bundle), len(o.File), MaxStatement, MaxStatement, MaxFile)
	}
	st, signed, err := pinsig.VerifyRoutes(o.Statement, o.Bundle, i.Trust.Root, i.Trust.Identity, i.Trust.Witnesses)
	if err != nil {
		return Admitted{}, err
	}
	if err := pinsig.AdmitRoutes(st, i.Environment, sha256.Sum256(i.Boot), i.Floor, signed, now, i.MaxAge); err != nil {
		return Admitted{}, err
	}
	if err := st.CheckFile(o.File); err != nil {
		return Admitted{}, err
	}
	if err := Bounds(i.Boot, o.File); err != nil {
		return Admitted{}, err
	}
	if i.Load == nil {
		return Admitted{}, fmt.Errorf("%w: the image has no loader", ErrLoad)
	}
	if err := i.Load(o.File); err != nil {
		return Admitted{}, fmt.Errorf("%w: %w", ErrLoad, err)
	}
	statement := sha256.Sum256(o.Statement)
	return Admitted{
		Sequence:        st.Sequence,
		StatementSHA256: hex.EncodeToString(statement[:]),
		FileSHA256:      hex.EncodeToString(st.File[:]),
		Signed:          signed,
		File:            o.File,
	}, nil
}
