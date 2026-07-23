/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package endorsement

import (
	"context"
	"time"

	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/view"

	token2 "github.com/LFDT-Panurus/panurus/token"
	"github.com/LFDT-Panurus/panurus/token/core/common"
	session2 "github.com/LFDT-Panurus/panurus/token/services/utils/json/session"
	"github.com/LFDT-Panurus/panurus/x/token/services/network/evm/client"
	"github.com/LFDT-Panurus/panurus/x/token/services/network/evm/eip712"
	"github.com/LFDT-Panurus/panurus/x/token/services/network/evm/keys"
	"github.com/LFDT-Panurus/panurus/x/token/services/network/evm/statedelta"
)

// receiveTimeout bounds how long a responder waits for the request on its session before giving up.
const receiveTimeout = 30 * time.Second

// Responder endorses a token request for one TMS. It is the EVM analog of the Fabric
// RequestApprovalResponderView, running the flow of design §6.2:
//
//	receive → authorize → validate → translate → sign → reply
//
// Every collaborator is injected so the flow is unit-testable without an FSC runtime or a live node,
// and so one Responder serves exactly one TMS (multi-TMS routing is the Service's job, keyed by
// TMSID). The responder never signs a digest handed to it: it recomputes the StateDelta from the
// validated actions and signs that, so a malicious initiator cannot get it to endorse a delta that
// does not match the request it validated (design §4.5).
type Responder struct {
	tmsID      token2.TMSID
	authorizer *Authorizer
	validator  RequestValidator
	pp         PublicParamsProvider
	signer     EndorserSigner
	domain     eip712.Domain

	// client and tokenState back the read-only validation ledger (getToken@blockTag).
	client     client.EVMClient
	tokenState client.Address
	blockTag   string
}

// NewResponder assembles a Responder for one TMS from its collaborators. An empty blockTag defaults
// to DefaultBlockTag.
func NewResponder(
	tmsID token2.TMSID,
	authorizer *Authorizer,
	validator RequestValidator,
	pp PublicParamsProvider,
	signer EndorserSigner,
	domain eip712.Domain,
	evmClient client.EVMClient,
	tokenState client.Address,
	blockTag string,
) *Responder {
	if blockTag == "" {
		blockTag = DefaultBlockTag
	}

	return &Responder{
		tmsID:      tmsID,
		authorizer: authorizer,
		validator:  validator,
		pp:         pp,
		signer:     signer,
		domain:     domain,
		client:     evmClient,
		tokenState: tokenState,
		blockTag:   blockTag,
	}
}

// Call implements the FSC responder view: receive the request on the context's session, endorse it,
// and reply. The session authenticates the caller, so authorization uses ts.Info().Caller rather
// than anything the request declares. A declined endorsement is sent back to the initiator as a
// response carrying the reason (so the initiator sees why), and also returned as the view's error.
func (r *Responder) Call(context view.Context) (any, error) {
	ts := session2.NewTypedSessionFromContext(context)

	var req EndorseRequest
	if err := ts.ReceiveTypedWithTimeout(TypeEndorseRequest, &req, receiveTimeout); err != nil {
		return nil, errors.Wrap(err, "failed to receive endorse request")
	}

	resp := r.Handle(context.Context(), ts.Info().Caller, &req)
	if err := ts.SendTyped(context.Context(), resp, TypeEndorseResponse); err != nil {
		return nil, errors.Wrap(err, "failed to send endorse response")
	}
	if err := resp.Error(); err != nil {
		return nil, err
	}

	return resp, nil
}

// Handle runs the endorsement decision for one request from the authenticated caller and returns the
// response to send back. It never returns an error: a refusal is a well-formed EndorseResponse with
// Err set, so the initiator always learns the outcome. Splitting it out from Call keeps the decision
// testable without a session.
func (r *Responder) Handle(ctx context.Context, caller view.Identity, req *EndorseRequest) *EndorseResponse {
	sig, err := r.endorse(ctx, caller, req)
	if err != nil {
		return &EndorseResponse{Err: err.Error()}
	}

	return &EndorseResponse{Signature: sig, EndorserAddress: r.signer.Address().Hex()}
}

// endorse is the decision proper: authorize, validate, translate, sign. It returns the signature or
// the first failure.
func (r *Responder) endorse(ctx context.Context, caller view.Identity, req *EndorseRequest) ([]byte, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if !r.tmsID.Equal(req.TMSID) {
		return nil, errors.Errorf("request targets tms [%s], this endorser serves [%s]", req.TMSID, r.tmsID)
	}
	if err := r.authorizer.Authorize(caller); err != nil {
		return nil, err
	}

	// public parameters this endorser binds the delta to: the bytes whose hash the contract checks,
	// and the on-chain version the contract requires at apply time.
	ppRaw, ppVersion, err := r.pp.PublicParams(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load public parameters")
	}

	// validate the request against on-chain state, read through the getToken ledger at blockTag.
	ledger := NewLedger(ctx, r.client, r.tokenState, r.blockTag)
	actions, meta, err := r.validator.UnmarshallAndVerifyWithMetadata(
		ctx,
		ledger,
		token2.RequestAnchor(req.Anchor),
		req.TokenRequest,
	)
	if err != nil {
		return nil, errors.Join(ErrValidation, err)
	}

	// translate the validated actions into the delta this endorser will sign.
	delta, err := r.translate(ctx, req, actions, meta, ppRaw, ppVersion)
	if err != nil {
		return nil, err
	}

	// recompute the digest and sign it. The digest is derived here, from the delta this endorser
	// built, never taken from the request.
	digest := eip712.Digest(r.domain, delta)

	return r.signer.Sign(digest)
}

// translate reconstructs the StateDelta from the validated actions, binding it to the public
// parameters and the token-request hash. The token-request hash is committed from the validator's
// TokenRequestToSign attribute (the anchor-bound message-to-sign), matching the hash the rest of the
// SDK stores, exactly as the Fabric responder does (responder.go: CommitTokenRequest(meta[trs])).
func (r *Responder) translate(
	ctx context.Context,
	req *EndorseRequest,
	actions []any,
	meta map[string][]byte,
	ppRaw []byte,
	ppVersion uint64,
) (*statedelta.StateDelta, error) {
	anchor, err := keys.AnchorFromTxID(req.Anchor)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid anchor [%s]", req.Anchor)
	}

	tr := statedelta.NewTranslator(anchor, ppRaw, ppVersion)
	for i, action := range actions {
		if err := tr.Write(ctx, action); err != nil {
			return nil, errors.Wrapf(err, "failed to translate action %d", i)
		}
	}
	if err := tr.AddPublicParamsDependency(); err != nil {
		return nil, errors.Wrap(err, "failed to add public parameters dependency")
	}
	if _, err := tr.CommitTokenRequest(meta[common.TokenRequestToSign], true); err != nil {
		return nil, errors.Wrap(err, "failed to commit token request")
	}

	return tr.StateDelta()
}

// compile-time check that *token.Validator satisfies RequestValidator, so the production wiring
// (tms.Validator()) can be injected directly.
var _ RequestValidator = (*token2.Validator)(nil)
