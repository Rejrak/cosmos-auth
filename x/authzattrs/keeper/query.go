package keeper

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"alpha/x/authzattrs/types"
)

type queryServer struct{ k Keeper }

func NewQueryServerImpl(k Keeper) types.QueryServer { return queryServer{k: k} }

var _ types.QueryServer = queryServer{}

func (q queryServer) Authorization(ctx context.Context, req *types.QueryAuthorizationRequest) (*types.QueryAuthorizationResponse, error) {
	if req == nil || req.MsgTypeUrl != types.MsgSendTypeURL {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	address, err := q.k.addressCodec.StringToBytes(req.Subject)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid subject")
	}
	canonical, err := q.k.addressCodec.BytesToString(address)
	if err != nil || canonical != req.Subject {
		return nil, status.Error(codes.InvalidArgument, "subject is not canonical")
	}
	record, found, err := q.k.GetAuthorization(ctx, req.Subject, req.MsgTypeUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &types.QueryAuthorizationResponse{Found: found, Authorization: record}, nil
}

func (q queryServer) CurrentIssuerSet(ctx context.Context, req *types.QueryCurrentIssuerSetRequest) (*types.QueryCurrentIssuerSetResponse, error) {
	if req == nil || req.PolicyId == "" || req.MsgTypeUrl != types.MsgSendTypeURL {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	issuerSetID, found, err := q.k.GetCurrentIssuerSet(ctx, req.PolicyId, req.MsgTypeUrl)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	if found && issuerSetID == 0 {
		return nil, status.Error(codes.Internal, "invalid current issuer set")
	}
	return &types.QueryCurrentIssuerSetResponse{Found: found, IssuerSetId: issuerSetID}, nil
}

func (q queryServer) LastAppliedBatchID(ctx context.Context, req *types.QueryLastAppliedBatchIDRequest) (*types.QueryLastAppliedBatchIDResponse, error) {
	if req == nil || req.IssuerSetId == 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	batchID, found, err := q.k.GetLastAppliedBatchID(ctx, req.IssuerSetId)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &types.QueryLastAppliedBatchIDResponse{Found: found, BatchId: batchID}, nil
}
