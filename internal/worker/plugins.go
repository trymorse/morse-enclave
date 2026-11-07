package worker

import (
	"context"
	"io"
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/plugins"
)

const (
	PluginCallPattern   = "POST /v1/plugins/call"
	PluginTokenPattern  = "POST /v1/plugins/token"
	PluginRevokePattern = "POST /v1/plugins/revoke"
)

var errPluginsSealedOnly = apierr.Invalid(http.StatusForbidden, "sealed_required", "A plugin's call holds the user's token for it, so the worker opens one only sealed.")

// PluginAdmission says only that a plugin request was opened: no server, no size, nothing the relay could keep
// beside the account that names the vendor.
type PluginAdmission struct{ admitted }

func (PluginAdmission) kind() admissionKind { return admitsPlugin }

// PluginGrant names the servers the relay switched off, which the worker then refuses all but revocations.
type PluginGrant struct {
	Off []string `json:"off,omitempty"`
}

func (PluginGrant) kind() grantKind { return grantsPlugin }

type openedPlugin struct {
	cuts
	req plugins.Request
}

func (w *InProcess) openPlugin(o Opening, kind plugins.Kind) (Admission, error) {
	if w.plugins == nil {
		return nil, errNoSuchRoute
	}
	if o.cek == nil {
		return nil, errPluginsSealedOnly
	}
	req, err := w.plugins.Open(kind, o.Body)
	if err != nil {
		return nil, contentRefusal(err)
	}
	return PluginAdmission{admitted: admitted{w.keep(o, &openedPlugin{cuts: newCuts(), req: req})}}, nil
}

func (o *openedPlugin) cut(reason measure.Cut) { o.cuts.cut(reason, true) }

func (o *openedPlugin) run(_ context.Context, w *InProcess, _ Handle, g Grant, reply http.ResponseWriter) Measured {
	pg, ok := g.(PluginGrant)
	if !ok {
		return unrunnable(reply)
	}
	rw := newReplyWriter(reply)
	answer, err := w.plugins.Run(o.cuts.run, o.req, pg.Off)
	var writeErr error
	if err == nil {
		writeErr = writeJSONBody(rw, func(out io.Writer) error {
			_, err := out.Write(answer)
			return err
		})
	} else {
		refuse(o.cuts.run, rw, err)
	}
	end := endingOf(o.cuts.client, writeErr, err)
	return Measured{Measurement: measure.Measurement{Outcome: end.outcome()}, Cut: end.cut(), Served: err == nil, Refusal: end.refusal(err)}
}
