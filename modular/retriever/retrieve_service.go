package retriever

import (
	"context"
	"cosmossdk.io/math"
	"errors"
	systemerrors "errors"
	"net/http"
	"sync/atomic"

	storage_types "github.com/bnb-chain/greenfield/x/storage/types"
	"github.com/forbole/juno/v4/common"
	"gorm.io/gorm"

	"github.com/bnb-chain/greenfield-storage-provider/base/types/gfsperrors"
	"github.com/bnb-chain/greenfield-storage-provider/core/spdb"
	"github.com/bnb-chain/greenfield-storage-provider/modular/retriever/types"
	"github.com/bnb-chain/greenfield-storage-provider/pkg/log"
)

var (
	ErrDanglingPointer = gfsperrors.Register(RetrieveModularName, http.StatusInternalServerError, 90001, "OoooH... request lost, try again later")
	ErrExceedRequest   = gfsperrors.Register(RetrieveModularName, http.StatusServiceUnavailable, 90002, "request exceed")
	ErrNoRecord        = gfsperrors.Register(RetrieveModularName, http.StatusNotFound, 90003, "no uploading record")
	ErrGfSpDB          = gfsperrors.Register(RetrieveModularName, http.StatusInternalServerError, 95202, "server slipped away, try again later")
)

var _ types.GfSpRetrieverServiceServer = &RetrieveModular{}

func (r *RetrieveModular) GfSpGetUserBuckets(
	ctx context.Context,
	req *types.GfSpGetUserBucketsRequest) (
	resp *types.GfSpGetUserBucketsResponse, err error) {
	ctx = log.Context(ctx, req)
	buckets, err := r.baseApp.GfBsDB().GetUserBuckets(common.HexToAddress(req.AccountId))
	if err != nil {
		log.CtxErrorw(ctx, "failed to get user buckets", "error", err)
		return
	}

	res := make([]*types.Bucket, 0)
	for _, bucket := range buckets {
		res = append(res, &types.Bucket{
			BucketInfo: &storage_types.BucketInfo{
				Owner:            bucket.Owner.String(),
				BucketName:       bucket.BucketName,
				Id:               math.NewUintFromBigInt(bucket.BucketID.Big()),
				SourceType:       storage_types.SourceType(storage_types.SourceType_value[bucket.SourceType]),
				CreateAt:         bucket.CreateTime,
				PaymentAddress:   bucket.PaymentAddress.String(),
				PrimarySpAddress: bucket.PrimarySpAddress.String(),
				ChargedReadQuota: bucket.ChargedReadQuota,
				Visibility:       storage_types.VisibilityType(storage_types.VisibilityType_value[bucket.Visibility]),
				BillingInfo: storage_types.BillingInfo{
					PriceTime:              0,
					TotalChargeSize:        0,
					SecondarySpObjectsSize: nil,
				},
				BucketStatus: storage_types.BucketStatus(storage_types.BucketStatus_value[bucket.Status]),
			},
			Removed:      bucket.Removed,
			DeleteAt:     bucket.DeleteAt,
			DeleteReason: bucket.DeleteReason,
			Operator:     bucket.Operator.String(),
			CreateTxHash: bucket.CreateTxHash.String(),
			UpdateTxHash: bucket.UpdateTxHash.String(),
			UpdateAt:     bucket.UpdateAt,
			UpdateTime:   bucket.UpdateTime,
		})
	}
	resp = &types.GfSpGetUserBucketsResponse{Buckets: res}
	log.CtxInfow(ctx, "succeed to get user buckets")
	return resp, nil
}

func (r *RetrieveModular) GfSpGetBucketReadQuota(
	ctx context.Context,
	req *types.GfSpGetBucketReadQuotaRequest) (
	*types.GfSpGetBucketReadQuotaResponse, error) {
	if req.GetBucketInfo() == nil {
		return nil, ErrDanglingPointer
	}
	defer atomic.AddInt64(&r.retrievingRequest, -1)
	if atomic.AddInt64(&r.retrievingRequest, 1) >
		atomic.LoadInt64(&r.maxRetrieveRequest) {
		return nil, ErrExceedRequest
	}
	bucketTraffic, err := r.baseApp.GfSpDB().GetBucketTraffic(
		req.GetBucketInfo().Id.Uint64(), req.GetYearMonth())
	if systemerrors.Is(err, gorm.ErrRecordNotFound) {
		return &types.GfSpGetBucketReadQuotaResponse{
			ChargedQuotaSize: req.GetBucketInfo().GetChargedReadQuota(),
			SpFreeQuotaSize:  r.freeQuotaPerBucket,
			ConsumedSize:     0,
		}, nil
	}
	if err != nil {
		log.Errorw("failed to get bucket traffic", "bucket_name", req.GetBucketInfo().GetBucketName(),
			"bucket_id", req.GetBucketInfo().Id.String(), "error", err)
		return &types.GfSpGetBucketReadQuotaResponse{Err: ErrGfSpDB}, nil
	}
	return &types.GfSpGetBucketReadQuotaResponse{
		ChargedQuotaSize: req.GetBucketInfo().GetChargedReadQuota(),
		SpFreeQuotaSize:  r.freeQuotaPerBucket,
		ConsumedSize:     bucketTraffic.ReadConsumedSize,
	}, nil
}

func (r *RetrieveModular) GfSpListBucketReadRecord(
	ctx context.Context,
	req *types.GfSpListBucketReadRecordRequest) (
	*types.GfSpListBucketReadRecordResponse,
	error) {
	if req.GetBucketInfo() == nil {
		return nil, ErrDanglingPointer
	}
	defer atomic.AddInt64(&r.retrievingRequest, -1)
	if atomic.AddInt64(&r.retrievingRequest, 1) >
		atomic.LoadInt64(&r.maxRetrieveRequest) {
		return nil, ErrExceedRequest
	}
	records, err := r.baseApp.GfSpDB().GetBucketReadRecord(req.GetBucketInfo().Id.Uint64(),
		&spdb.TrafficTimeRange{
			StartTimestampUs: req.StartTimestampUs,
			EndTimestampUs:   req.EndTimestampUs,
			LimitNum:         int(req.MaxRecordNum),
		})
	if systemerrors.Is(err, gorm.ErrRecordNotFound) {
		return &types.GfSpListBucketReadRecordResponse{
			NextStartTimestampUs: 0,
		}, nil
	}
	if err != nil {
		log.Errorw("failed to list bucket read record",
			"bucket_name", req.GetBucketInfo().GetBucketName(),
			"bucket_id", req.GetBucketInfo().Id.String(), "error", err)
		return &types.GfSpListBucketReadRecordResponse{Err: ErrGfSpDB}, nil
	}
	var nextStartTimestampUs int64
	readRecords := make([]*types.ReadRecord, 0)
	for _, r := range records {
		readRecords = append(readRecords, &types.ReadRecord{
			ObjectName:     r.ObjectName,
			ObjectId:       r.ObjectID,
			AccountAddress: r.UserAddress,
			TimestampUs:    r.ReadTimestampUs,
			ReadSize:       r.ReadSize,
		})
		if r.ReadTimestampUs >= nextStartTimestampUs {
			nextStartTimestampUs = r.ReadTimestampUs + 1
		}
	}
	resp := &types.GfSpListBucketReadRecordResponse{
		ReadRecords:          readRecords,
		NextStartTimestampUs: nextStartTimestampUs,
	}
	return resp, nil
}

func (r *RetrieveModular) GfSpQueryUploadProgress(
	ctx context.Context,
	req *types.GfSpQueryUploadProgressRequest) (
	*types.GfSpQueryUploadProgressResponse, error) {
	job, err := r.baseApp.GfSpDB().GetJobByObjectID(req.GetObjectId())
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &types.GfSpQueryUploadProgressResponse{
				Err: ErrNoRecord,
			}, nil
		}
		return &types.GfSpQueryUploadProgressResponse{
			Err: ErrGfSpDB,
		}, nil
	}
	return &types.GfSpQueryUploadProgressResponse{
		State: job.JobState,
	}, nil
}
