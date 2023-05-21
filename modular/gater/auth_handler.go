package gater

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/bnb-chain/greenfield-storage-provider/base/types/gfsperrors"
	"github.com/bnb-chain/greenfield-storage-provider/base/types/gfspserver"
	"github.com/gogo/protobuf/jsonpb"

	"github.com/bnb-chain/greenfield-storage-provider/model"
	"github.com/bnb-chain/greenfield-storage-provider/pkg/log"
)

const (
	MaxExpiryAgeInSec int32  = 3600 * 24 * 7 // 7 days
	ExpiryDateFormat  string = time.RFC3339
)

// requestNonceHandler handle requestNonce request
func (g *GateModular) requestNonceHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		b      bytes.Buffer
		reqCtx = NewRequestContext(r)
	)
	defer func() {
		reqCtx.Cancel()
		if err != nil {
			reqCtx.SetError(gfsperrors.MakeGfSpError(err))
			log.CtxErrorw(reqCtx.Context(), "failed to request nonce", "req_info", reqCtx.String())
			MakeErrorResponse(w, gfsperrors.MakeGfSpError(err))
		}
	}()

	req := &gfspserver.GetAuthNonceRequest{
		AccountId: reqCtx.request.Header.Get(model.GnfdUserAddressHeader),
		Domain:    reqCtx.request.Header.Get(model.GnfdOffChainAuthAppDomainHeader),
	}
	ctx := log.Context(context.Background(), req)
	resp, err := g.baseApp.GfSpClient().GetAuthNonce(ctx, req)

	if err != nil {
		log.CtxErrorw(reqCtx.Context(), "failed to GetAuthNonce", "error", err)
		return
	}
	m := jsonpb.Marshaler{EmitDefaults: true, OrigName: true, EnumsAsInts: true}
	if err = m.Marshal(&b, resp); err != nil {
		log.CtxErrorw(reqCtx.Context(), "failed to GetAuthNonce", "error", err)
		return
	}

	w.Header().Set(model.ContentTypeHeader, model.ContentTypeJSONHeaderValue)
	w.Write(b.Bytes())
}

func (g *GateModular) updateUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err           error
		b             bytes.Buffer
		reqCtx        = NewRequestContext(r)
		account       string
		userPublicKey string
		domain        string
		origin        string
		nonce         string
		expiryDateStr string
	)

	defer func() {
		reqCtx.Cancel()
		if err != nil {
			reqCtx.SetError(gfsperrors.MakeGfSpError(err))
			log.CtxErrorw(reqCtx.Context(), "failed to updateUserPublicKey", "req_info", reqCtx.String())
			MakeErrorResponse(w, gfsperrors.MakeGfSpError(err))
		}
	}()

	if reqCtx.NeedVerifySignature() {
		accAddress, err := g.VerifySignature(reqCtx)
		if err != nil {
			log.CtxErrorw(reqCtx.Context(), "failed to verify signature", "error", err)
			return
		}
		account = accAddress.String()
	}

	domain = reqCtx.request.Header.Get(model.GnfdOffChainAuthAppDomainHeader)
	origin = reqCtx.request.Header.Get("Origin")
	nonce = reqCtx.request.Header.Get(model.GnfdOffChainAuthAppRegNonceHeader)
	userPublicKey = reqCtx.request.Header.Get(model.GnfdOffChainAuthAppRegPublicKeyHeader)
	expiryDateStr = reqCtx.request.Header.Get(model.GnfdOffChainAuthAppRegExpiryDateHeader)

	// validate headers
	if domain == "" || domain != origin {
		log.CtxErrorw(reqCtx.Context(), "failed to updateUserPublicKey due to bad origin or domain")
		err = ErrInvalidDomainHeader
		return
	}

	if userPublicKey == "" {
		log.CtxErrorw(reqCtx.Context(), "failed to updateUserPublicKey due to bad userPublicKey")
		err = ErrInvalidPublicKeyHeader
		return
	}

	req := &gfspserver.GetAuthNonceRequest{
		AccountId: account,
		Domain:    domain,
	}
	ctx := log.Context(context.Background(), req)
	getAuthNonceResp, err := g.baseApp.GfSpClient().GetAuthNonce(ctx, req)

	if err != nil {
		log.CtxErrorw(reqCtx.Context(), "failed to GetAuthNonce", "error", err)
		return
	}

	nonceInt, err := strconv.Atoi(nonce)
	if err != nil || int(getAuthNonceResp.NextNonce) != nonceInt { // nonce must be the same as NextNonce
		log.CtxErrorw(reqCtx.Context(), "failed to updateUserPublicKey due to bad nonce")
		err = ErrInvalidRegNonceHeader
		return
	}

	expiryDate, err := time.Parse(ExpiryDateFormat, expiryDateStr)
	if err != nil {
		log.CtxErrorw(reqCtx.Context(), "failed to updateUserPublicKey due to InvalidExpiryDateHeader")
		err = ErrInvalidExpiryDateHeader
		return
	}
	log.Infof("%s", time.Until(expiryDate).Seconds())
	log.Infof("%s", MaxExpiryAgeInSec)
	expiryAge := int32(time.Until(expiryDate).Seconds())
	if MaxExpiryAgeInSec < expiryAge || expiryAge < 0 {
		err = ErrInvalidExpiryDateHeader
		log.CtxErrorw(reqCtx.Context(), "failed to updateUserPublicKey due to InvalidExpiryDateHeader")
		return
	}

	requestSignature := reqCtx.request.Header.Get(model.GnfdAuthorizationHeader)
	personalSignSignaturePrefix := signaturePrefix(model.SignTypePersonal, model.SignAlgorithm)
	signedMsg, _, err := parseSignedMsgAndSigFromRequest(requestSignature[len(personalSignSignaturePrefix):])
	if err != nil {
		log.CtxErrorw(reqCtx.Context(), "failed to updateUserPublicKey when parseSignedMsgAndSigFromRequest")
		return
	}
	err = g.verifySignedContent(*signedMsg, domain, nonce, userPublicKey, expiryDateStr)
	if err != nil {
		log.CtxErrorw(reqCtx.Context(), "failed to updateUserPublicKey due to bad signed content.")
		return
	}

	updateUserPublicKeyReq := &gfspserver.UpdateUserPublicKeyRequest{
		AccountId:     account,
		Domain:        domain,
		CurrentNonce:  getAuthNonceResp.CurrentNonce,
		Nonce:         int32(nonceInt),
		UserPublicKey: userPublicKey,
		ExpiryDate:    expiryDate.UnixMilli(),
	}
	updateUserPublicKeyResp, err := g.baseApp.GfSpClient().UpdateUserPublicKey(ctx, updateUserPublicKeyReq)
	if err != nil {
		log.Errorw("failed to updateUserPublicKey when saving key")
		return
	}

	m := jsonpb.Marshaler{EmitDefaults: true, OrigName: true, EnumsAsInts: true}
	if err = m.Marshal(&b, updateUserPublicKeyResp); err != nil {
		log.Errorw("failed to UpdateUserPublicKey", "error", err)
		return
	}

	w.Header().Set(model.ContentTypeHeader, model.ContentTypeJSONHeaderValue)
	w.Write(b.Bytes())
}

func (g *GateModular) verifySignedContent(signedContent string, expectedDomain string, expectedNonce string, expectedPublicKey string, expectedExpiryDate string) *gfsperrors.GfSpError {
	pattern := `(.+) wants you to sign in with your BNB Greenfield account:\n*(.+)\n*Register your identity public key (.+)\n*URI: (.+)\n*Version: (.+)\n*Chain ID: (.+)\n*Issued At: (.+)\n*Expiration Time: (.+)\n*Resources:((?:\n- SP .+ \(name:.+\) with nonce: \d+)+)`

	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(signedContent)
	if len(match) < 4 {
		return ErrSignedMsgNotMatchTemplate
	}
	// Extract variable values
	dappDomain := match[1]
	// userAcct := match[2]  // unused, but keep this line here to indicate the matched details so that they could be useful in the future.
	publicKey := match[3]
	// eip4361URI := match[4] // unused, but keep this line here to indicate the matched details so that they could be useful in the future.
	// eip4361Version := match[5] // unused, but keep this line here to indicate the matched details so that they could be useful in the future.
	// eip4361ChainId := match[6] // unused, but keep this line here to indicate the matched details so that they could be useful in the future.
	// eip4361IssuedAt := match[7] // unused, but keep this line here to indicate the matched details so that they could be useful in the future.
	eip4361ExpirationTime := match[8]

	spsText := match[9]
	spsPattern := `- SP (.+) \(name:(.+\S)\) with nonce: (\d+)`
	spsRe := regexp.MustCompile(spsPattern)
	spsMatch := spsRe.FindAllStringSubmatch(spsText, -1)

	var found = false
	for _, match := range spsMatch {
		spAddress := match[1]
		// spName := match[2]  // keep this line here to indicate match[2] means spName
		spNonce := match[3]
		if spAddress == g.baseApp.OperateAddress() {
			found = true
			if expectedNonce != spNonce { // nonce doesn't match
				return ErrSignedMsgNotMatchTemplate
			}
		}
	}
	if !found { // the signed content is not for this SP  (g.config.SpOperatorAddress)
		return ErrSignedMsgNotMatchSPAddr
	}
	if dappDomain != expectedDomain {
		return ErrSignedMsgNotMatchTemplate
	}
	if publicKey != expectedPublicKey {
		return ErrSignedMsgNotMatchTemplate
	}
	if eip4361ExpirationTime != expectedExpiryDate {
		return ErrSignedMsgNotMatchTemplate
	}

	return nil
}
