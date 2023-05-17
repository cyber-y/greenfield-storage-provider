package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bnb-chain/greenfield/types/s3util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gogo/protobuf/jsonpb"

	"github.com/bnb-chain/greenfield-storage-provider/model"
	"github.com/bnb-chain/greenfield-storage-provider/pkg/log"
	metatypes "github.com/bnb-chain/greenfield-storage-provider/service/metadata/types"
	"github.com/bnb-chain/greenfield-storage-provider/util"
)

// getUserBucketsHandler handle get object request
func (gateway *Gateway) getUserBucketsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err            error
		b              bytes.Buffer
		errDescription *errorDescription
		reqContext     *requestContext
	)

	reqContext = newRequestContext(r)
	defer func() {
		if errDescription != nil {
			_ = errDescription.errorJSONResponse(w, reqContext)
		}
		if errDescription != nil && errDescription.statusCode != http.StatusOK {
			log.Errorf("action(%v) statusCode(%v) %v", getUserBucketsRouterName, errDescription.statusCode, reqContext.generateRequestDetail())
		} else {
			log.Infof("action(%v) statusCode(200) %v", getUserBucketsRouterName, reqContext.generateRequestDetail())
		}
	}()

	if gateway.metadata == nil {
		log.Error("failed to get user buckets due to not config metadata")
		errDescription = NotExistComponentError
		return
	}

	if ok := common.IsHexAddress(r.Header.Get(model.GnfdUserAddressHeader)); !ok {
		log.Errorw("failed to check account id", "account_id", reqContext.accountID, "error", err)
		errDescription = InvalidAddress
		return
	}

	req := &metatypes.GetUserBucketsRequest{
		AccountId: r.Header.Get(model.GnfdUserAddressHeader),
	}
	ctx := log.Context(context.Background(), req)
	resp, err := gateway.metadata.GetUserBuckets(ctx, req)
	if err != nil {
		log.Errorf("failed to get user buckets", "error", err)
		errDescription = makeErrorDescription(err)
		return
	}

	m := jsonpb.Marshaler{EmitDefaults: true, OrigName: true, EnumsAsInts: true}
	if err = m.Marshal(&b, resp); err != nil {
		log.Errorf("failed to get user buckets", "error", err)
		errDescription = makeErrorDescription(err)
		return
	}

	w.Header().Set(model.ContentTypeHeader, model.ContentTypeJSONHeaderValue)
	w.Write(b.Bytes())
}

// listObjectsByBucketNameHandler handle list objects by bucket name request
func (gateway *Gateway) listObjectsByBucketNameHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err                      error
		b                        bytes.Buffer
		maxKeys                  uint64
		errDescription           *errorDescription
		reqContext               *requestContext
		ok                       bool
		requestBucketName        string
		requestMaxKeys           string
		requestStartAfter        string
		requestContinuationToken string
		requestDelimiter         string
		requestPrefix            string
		continuationToken        string
		decodedContinuationToken []byte
		queryParams              url.Values
	)

	reqContext = newRequestContext(r)
	defer func() {
		if errDescription != nil {
			_ = errDescription.errorJSONResponse(w, reqContext)
		}
		if errDescription != nil && errDescription.statusCode != http.StatusOK {
			log.Errorf("action(%v) statusCode(%v) %v", listObjectsByBucketRouterName, errDescription.statusCode, reqContext.generateRequestDetail())
		} else {
			log.Infof("action(%v) statusCode(200) %v", listObjectsByBucketRouterName, reqContext.generateRequestDetail())
		}
	}()

	if gateway.metadata == nil {
		log.Error("failed to list objects by bucket name due to not config metadata")
		errDescription = NotExistComponentError
		return
	}

	queryParams = reqContext.request.URL.Query()
	requestBucketName = reqContext.bucketName
	requestMaxKeys = queryParams.Get(model.ListObjectsMaxKeysQuery)
	requestStartAfter = queryParams.Get(model.ListObjectsStartAfterQuery)
	requestContinuationToken = queryParams.Get(model.ListObjectsContinuationTokenQuery)
	requestDelimiter = queryParams.Get(model.ListObjectsDelimiterQuery)
	requestPrefix = queryParams.Get(model.ListObjectsPrefixQuery)

	if err = s3util.CheckValidBucketName(requestBucketName); err != nil {
		log.Errorw("failed to check bucket name", "bucket_name", requestBucketName, "error", err)
		errDescription = InvalidBucketName
		return
	}

	if requestMaxKeys != "" {
		if maxKeys, err = util.StringToUint64(requestMaxKeys); err != nil || maxKeys == 0 {
			log.Errorw("failed to parse or check maxKeys", "max_keys", requestMaxKeys, "error", err)
			errDescription = InvalidMaxKeys
			return
		}
	}

	if requestStartAfter != "" {
		if err = s3util.CheckValidObjectName(requestStartAfter); err != nil {
			log.Errorw("failed to check startAfter", "start_after", requestStartAfter, "error", err)
			errDescription = InvalidStartAfter
			return
		}
	}

	if requestContinuationToken != "" {
		decodedContinuationToken, err = base64.StdEncoding.DecodeString(requestContinuationToken)
		if err != nil {
			log.Errorw("failed to check requestContinuationToken", "continuation_token", requestContinuationToken, "error", err)
			errDescription = InvalidContinuationToken
			return
		}
		continuationToken = string(decodedContinuationToken)

		if err = s3util.CheckValidObjectName(continuationToken); err != nil {
			log.Errorw("failed to check requestContinuationToken", "continuation_token", continuationToken, "error", err)
			errDescription = InvalidContinuationToken
			return
		}

		if !strings.HasPrefix(continuationToken, requestPrefix) {
			log.Errorw("failed to check requestContinuationToken", "continuation_token", continuationToken, "prefix", requestPrefix, "error", err)
			errDescription = InvalidContinuationToken
			return
		}
	}

	if ok = checkValidObjectPrefix(requestPrefix); !ok {
		log.Errorw("failed to check requestPrefix", "prefix", requestPrefix, "error", err)
		errDescription = InvalidPrefix
		return
	}

	if requestContinuationToken == "" {
		continuationToken = requestStartAfter
	}

	req := &metatypes.ListObjectsByBucketNameRequest{
		BucketName:        requestBucketName,
		MaxKeys:           maxKeys,
		StartAfter:        requestStartAfter,
		ContinuationToken: continuationToken,
		Delimiter:         requestDelimiter,
		Prefix:            requestPrefix,
	}

	ctx := log.Context(context.Background(), req)
	resp, err := gateway.metadata.ListObjectsByBucketName(ctx, req)
	if err != nil {
		log.Errorf("failed to list objects by bucket name", "error", err)
		errDescription = makeErrorDescription(err)
		return
	}

	m := jsonpb.Marshaler{EmitDefaults: true, OrigName: true, EnumsAsInts: true}
	if err = m.Marshal(&b, resp); err != nil {
		log.Errorf("failed to list objects by bucket name", "error", err)
		errDescription = makeErrorDescription(err)
		return
	}

	w.Header().Set(model.ContentTypeHeader, model.ContentTypeJSONHeaderValue)
	w.Write(b.Bytes())
}

// listExpiredBucketsBySpHandler handle list expired buckets by sp request
func (gateway *Gateway) listExpiredBucketsBySpHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err              error
		b                bytes.Buffer
		errDescription   *errorDescription
		reqContext       *requestContext
		createAt         string
		primarySpAddress string
		limit            string
		queryParams      url.Values
	)

	reqContext = newRequestContext(r)
	defer func() {
		if errDescription != nil {
			_ = errDescription.errorJSONResponse(w, reqContext)
		}
		if errDescription != nil && errDescription.statusCode != http.StatusOK {
			log.Errorf("action(%v) statusCode(%v) %v", "listExpiredBucketsBySpHandler", errDescription.statusCode, reqContext.generateRequestDetail())
		} else {
			log.Infof("action(%v) statusCode(200) %v", "listExpiredBucketsBySpHandler", reqContext.generateRequestDetail())
		}
	}()

	if gateway.metadata == nil {
		log.Error("failed to list expired buckets by sp due to not config metadata")
		errDescription = NotExistComponentError
		return
	}

	queryParams = reqContext.request.URL.Query()
	createAt = queryParams.Get("create_at")
	primarySpAddress = queryParams.Get("primary_sp_address")
	limit = queryParams.Get("limit")

	createAtInt64, err := strconv.ParseInt(createAt, 10, 64)
	limitInt64, err := strconv.ParseInt(limit, 10, 64)

	ctx := log.Context(context.Background())
	resp, err := gateway.metadata.ListExpiredBucketsBySp(ctx, createAtInt64, primarySpAddress, limitInt64)
	if err != nil {
		log.Errorf("failed to list objects by bucket name", "error", err)
		errDescription = makeErrorDescription(err)
		return
	}

	response := metatypes.ListExpiredBucketsBySpResponse{
		Buckets: resp,
	}

	m := jsonpb.Marshaler{EmitDefaults: true, OrigName: true, EnumsAsInts: true}
	if err = m.Marshal(&b, &response); err != nil {
		log.Errorf("failed to list expired buckets by sp", "error", err)
		errDescription = makeErrorDescription(err)
		return
	}

	w.Header().Set(model.ContentTypeHeader, model.ContentTypeJSONHeaderValue)
	w.Write(b.Bytes())
}
