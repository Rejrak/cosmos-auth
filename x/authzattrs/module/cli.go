package authzattrs

import (
	"fmt"
	"os"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/spf13/cobra"

	"alpha/x/authzattrs/types"
)

func (AppModule) GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Authorization attribute transactions",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	cmd.AddCommand(newSubmitAuthzBatchCmd())
	return cmd
}

func newSubmitAuthzBatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "submit-authz-batch <batch-file>",
		Short: "Submit an already signed authorization batch",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			msg, err := buildBatchUpsertMessage(clientCtx, args[0])
			if err != nil {
				return err
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func buildBatchUpsertMessage(clientCtx client.Context, path string) (*types.MsgBatchUpsertAuthorizations, error) {
	from := clientCtx.GetFromAddress()
	if len(from) == 0 {
		return nil, fmt.Errorf("--from identity is required")
	}
	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorization batch: %w", err)
	}
	if len(bz) == 0 {
		return nil, fmt.Errorf("authorization batch file is empty")
	}
	var batch types.AuthorizationBatch
	if err := batch.Unmarshal(bz); err != nil {
		return nil, fmt.Errorf("decode authorization batch protobuf: %w", err)
	}
	if batch.SignDoc == nil {
		return nil, fmt.Errorf("authorization batch sign_doc is required")
	}
	if len(batch.Signatures) == 0 {
		return nil, fmt.Errorf("authorization batch signatures are required")
	}
	return &types.MsgBatchUpsertAuthorizations{Submitter: from.String(), Batch: &batch}, nil
}
