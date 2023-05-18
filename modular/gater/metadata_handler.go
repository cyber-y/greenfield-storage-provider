package gater

import (
	"bytes"
	"github.com/bnb-chain/greenfield-storage-provider/base/types/gfsperrors"
	"github.com/bnb-chain/greenfield-storage-provider/modular/retriever/types"
	"net/http"

	"github.com/cosmos/gogoproto/jsonpb"
	"github.com/ethereum/go-ethereum/common"

	"github.com/bnb-chain/greenfield-storage-provider/model"
	"github.com/bnb-chain/greenfield-storage-provider/pkg/log"
)

// getUserBucketsHandler handle get object request
func (g *GateModular) getUserBucketsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		b      bytes.Buffer
		reqCtx = NewRequestContext(r)
	)
	defer func() {
		reqCtx.Cancel()
		if err != nil {
			reqCtx.SetError(gfsperrors.MakeGfSpError(err))
			log.CtxErrorw(reqCtx.Context(), "failed to get user buckets", reqCtx.String())
			MakeErrorResponse(w, err)
		}
	}()

	if ok := common.IsHexAddress(r.Header.Get(model.GnfdUserAddressHeader)); !ok {
		log.Errorw("failed to check account id", "account_id", reqCtx.account, "error", err)
		err = ErrInvalidHeader
		return
	}

	resp, err := g.baseApp.GfSpClient().GetUserBuckets(reqCtx.Context(), r.Header.Get(model.GnfdUserAddressHeader))
	if err != nil {
		log.CtxErrorw(reqCtx.Context(), "failed to get user buckets", "error", err)
		return
	}

	grpcResponse := &types.GfSpGetUserBucketsResponse{
		Buckets: resp,
	}

	m := jsonpb.Marshaler{EmitDefaults: true, OrigName: true, EnumsAsInts: true}
	if err = m.Marshal(&b, grpcResponse); err != nil {
		log.CtxErrorw(reqCtx.Context(), "failed to get user buckets", "error", err)
		return
	}

	w.Header().Set(model.ContentTypeHeader, model.ContentTypeJSONHeaderValue)
	w.Write(b.Bytes())
}
