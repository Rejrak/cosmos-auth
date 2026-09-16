package authzattrs

import (
	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"

	"alpha/x/authzattrs/types"
)

func (AppModule) GenerateGenesisState(simState *module.SimulationState) {
	simState.GenState[types.ModuleName] = simState.Cdc.MustMarshalJSON(types.DefaultGenesis())
}

func (AppModule) RegisterStoreDecoder(simtypes.StoreDecoderRegistry) {}

func (AppModule) WeightedOperations(module.SimulationState) []simtypes.WeightedOperation {
	return nil
}

func (AppModule) ProposalMsgs(module.SimulationState) []simtypes.WeightedProposalMsg {
	return nil
}
