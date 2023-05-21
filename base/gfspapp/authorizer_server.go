package gfspapp

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bnb-chain/greenfield-storage-provider/base/types/gfsperrors"
	"github.com/bnb-chain/greenfield-storage-provider/base/types/gfspserver"
	coremodule "github.com/bnb-chain/greenfield-storage-provider/core/module"
	"github.com/bnb-chain/greenfield-storage-provider/pkg/log"
)

var _ gfspserver.GfSpAuthorizationServiceServer = &GfSpBaseApp{}

const (
	OffChainAuthSigExpiryAgeInSec int32 = 60 * 5 // in 300 seconds
)

func (g *GfSpBaseApp) GfSpVerifyAuthorize(
	ctx context.Context,
	req *gfspserver.GfSpAuthorizeRequest) (
	*gfspserver.GfSpAuthorizeResponse, error) {
	ctx = log.WithValue(ctx, log.CtxKeyBucketName, req.GetBucketName())
	ctx = log.WithValue(ctx, log.CtxKeyObjectName, req.GetObjectName())
	log.CtxDebugw(ctx, "begin to authorize", "user", req.GetUserAccount(), "op_type", req.GetAuthType())
	allow, err := g.authorizer.VerifyAuthorize(ctx, coremodule.AuthOpType(req.GetAuthType()),
		req.GetUserAccount(), req.GetBucketName(), req.GetObjectName())
	log.CtxDebugw(ctx, "finish to authorize", "user", req.GetUserAccount(), "op_type", req.GetAuthType(),
		"allow", allow, "error", err)
	return &gfspserver.GfSpAuthorizeResponse{
		Err:     gfsperrors.MakeGfSpError(err),
		Allowed: allow,
	}, nil
}

// GetAuthNonce get the auth nonce for which the Dapp or client can generate EDDSA key pairs.
func (g *GfSpBaseApp) GetAuthNonce(ctx context.Context, req *gfspserver.GetAuthNonceRequest) (*gfspserver.GetAuthNonceResponse, error) {
	domain := req.Domain

	ctx = log.Context(ctx, req)
	authKey, err := g.gfSpDB.GetAuthKey(req.AccountId, domain)
	if err != nil {
		log.CtxErrorw(ctx, "failed to GetAuthKey", "error", err)
		return nil, err
	}
	resp := &gfspserver.GetAuthNonceResponse{
		CurrentNonce:     authKey.CurrentNonce,
		NextNonce:        authKey.NextNonce,
		CurrentPublicKey: authKey.CurrentPublicKey,
		ExpiryDate:       authKey.ExpiryDate.UnixMilli(),
	}
	log.CtxInfow(ctx, "succeed to GetAuthNonce")
	return resp, nil
}

// UpdateUserPublicKey updates the user public key once the Dapp or client generates the EDDSA key pairs.
func (g *GfSpBaseApp) UpdateUserPublicKey(ctx context.Context, req *gfspserver.UpdateUserPublicKeyRequest) (*gfspserver.UpdateUserPublicKeyResponse, error) {
	err := g.gfSpDB.UpdateAuthKey(req.AccountId, req.Domain, req.CurrentNonce, req.Nonce, req.UserPublicKey, time.UnixMilli(req.ExpiryDate))
	if err != nil {
		log.Errorw("failed to updateUserPublicKey when saving key")
		return nil, err
	}
	resp := &gfspserver.UpdateUserPublicKeyResponse{
		Result: true,
	}
	log.CtxInfow(ctx, "succeed to UpdateUserPublicKey")
	return resp, nil
}

// VerifyOffChainSignature verifies the signature signed by user's EDDSA private key.
func (g *GfSpBaseApp) VerifyOffChainSignature(ctx context.Context, req *gfspserver.VerifyOffChainSignatureRequest) (*gfspserver.VerifyOffChainSignatureResponse, error) {

	signedMsg := req.RealMsgToSign
	sigString := req.OffChainSig

	signature, err := hex.DecodeString(sigString)
	if err != nil {
		return nil, err
	}

	getAuthNonceReq := &gfspserver.GetAuthNonceRequest{
		AccountId: req.AccountId,
		Domain:    req.Domain,
	}
	getAuthNonceResp, err := g.GetAuthNonce(ctx, getAuthNonceReq)
	if err != nil {
		return nil, err
	}
	userPublicKey := getAuthNonceResp.CurrentPublicKey

	// signedMsg must be formatted as `${actionContent}_${expiredTimestamp}` and timestamp must be within $OffChainAuthSigExpiryAgeInSec seconds, actionContent could be any string
	signedMsgParts := strings.Split(signedMsg, "_")
	if len(signedMsgParts) < 2 {
		err = fmt.Errorf("signed msg must be formated as ${actionContent}_${expiredTimestamp}")
		return nil, err
	}

	signedMsgExpiredTimestamp, err := strconv.Atoi(signedMsgParts[len(signedMsgParts)-1])
	if err != nil {
		err = fmt.Errorf("expiredTimestamp in signed msg must be a unix epoch time in milliseconds")
		return nil, err
	}
	expiredAge := time.Until(time.UnixMilli(int64(signedMsgExpiredTimestamp))).Seconds()
	// todo clyde.meng output better error message
	if float64(OffChainAuthSigExpiryAgeInSec) < expiredAge || expiredAge < 0 { // nonce must be the same as NextNonce
		err = fmt.Errorf("expiredTimestamp in signed msg must be within %d seconds", OffChainAuthSigExpiryAgeInSec)
		return nil, err
	}

	err = VerifyEddsaSignature(userPublicKey, signature, []byte(signedMsg))
	if err != nil {
		return nil, err
	}
	log.Infof("verifyOffChainSignature: err %s", err)
	resp := &gfspserver.VerifyOffChainSignatureResponse{
		Result: true,
	}
	log.CtxInfow(ctx, "succeed to VerifyOffChainSignature")
	return resp, nil
}
