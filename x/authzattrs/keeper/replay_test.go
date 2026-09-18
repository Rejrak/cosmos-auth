package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
)

func TestBatchReplayStorageAndValidation(t *testing.T) {
	f := initFixture(t)

	batchID, found, err := f.keeper.GetLastAppliedBatchID(f.ctx, 1)
	require.NoError(t, err)
	require.False(t, found)
	require.Zero(t, batchID)

	_, _, err = f.keeper.GetLastAppliedBatchID(f.ctx, 0)
	require.ErrorIs(t, err, types.ErrInvalidBatchSignDoc)
	require.ErrorIs(t, f.keeper.SetLastAppliedBatchID(f.ctx, 0, 1), types.ErrInvalidBatchSignDoc)
	require.ErrorIs(t, f.keeper.SetLastAppliedBatchID(f.ctx, 1, 0), types.ErrInvalidBatchSignDoc)
	require.ErrorIs(t, f.keeper.ValidateBatchReplay(f.ctx, 0, 1), types.ErrInvalidBatchSignDoc)
	require.ErrorIs(t, f.keeper.ValidateBatchReplay(f.ctx, 1, 0), types.ErrInvalidBatchSignDoc)

	require.NoError(t, f.keeper.ValidateBatchReplay(f.ctx, 1, 10))
	_, found, err = f.keeper.GetLastAppliedBatchID(f.ctx, 1)
	require.NoError(t, err)
	require.False(t, found, "replay validation must not write first batch ID")

	require.NoError(t, f.keeper.SetLastAppliedBatchID(f.ctx, 1, 10))
	batchID, found, err = f.keeper.GetLastAppliedBatchID(f.ctx, 1)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint64(10), batchID)

	require.NoError(t, f.keeper.ValidateBatchReplay(f.ctx, 1, 11))
	require.ErrorIs(t, f.keeper.ValidateBatchReplay(f.ctx, 1, 10), types.ErrBatchReplay)
	require.ErrorIs(t, f.keeper.ValidateBatchReplay(f.ctx, 1, 9), types.ErrBatchReplay)
	batchID, found, err = f.keeper.GetLastAppliedBatchID(f.ctx, 1)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint64(10), batchID, "replay validation must not mutate existing state")

	require.NoError(t, f.keeper.SetLastAppliedBatchID(f.ctx, 2, 100))
	require.NoError(t, f.keeper.ValidateBatchReplay(f.ctx, 1, 11))
	require.ErrorIs(t, f.keeper.ValidateBatchReplay(f.ctx, 2, 100), types.ErrBatchReplay)
}
