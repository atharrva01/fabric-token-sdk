/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package endorsement

import (
	"context"

	"github.com/hyperledger-labs/fabric-smart-client/platform/view/view"
	"go.opentelemetry.io/otel/trace"
)

// fakeContext is a minimal view.Context for the endorsement tests: it carries a context.Context, and
// (for the gate test) hands the initiator a session per party via GetSession and the responder its
// own session via Session. Everything the endorsement views do not touch panics, so an unexpected
// dependency surfaces loudly rather than silently.
type fakeContext struct {
	ctx      context.Context
	me       view.Identity
	sessions map[string]view.Session // keyed by party UniqueID, for GetSession (initiator side)
	own      view.Session            // for Session() (responder side)
}

func (c *fakeContext) Context() context.Context { return c.ctx }
func (c *fakeContext) ID() string               { return "fake" }
func (c *fakeContext) Me() view.Identity        { return c.me }

func (c *fakeContext) GetSession(_ view.View, party view.Identity, _ ...view.View) (view.Session, error) {
	return c.sessions[party.UniqueID()], nil
}

func (c *fakeContext) Session() view.Session { return c.own }

// unused view.Context surface: these must never be called by the endorsement views under test.
func (c *fakeContext) StartSpanFrom(ctx context.Context, _ string, _ ...trace.SpanStartOption) (context.Context, trace.Span) {
	return ctx, trace.SpanFromContext(ctx)
}

func (c *fakeContext) GetService(any) (any, error) {
	panic("GetService not supported in fake context")
}

func (c *fakeContext) RunView(view.View, ...view.RunViewOption) (any, error) {
	panic("RunView not supported in fake context")
}
func (c *fakeContext) IsMe(view.Identity) bool { return false }
func (c *fakeContext) Initiator() view.View    { return nil }

func (c *fakeContext) GetSessionByID(string, view.Identity) (view.Session, error) {
	panic("GetSessionByID not supported in fake context")
}
func (c *fakeContext) OnError(func()) {}

// compile-time check that the fake satisfies the FSC contract.
var _ view.Context = (*fakeContext)(nil)
