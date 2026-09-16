package types

import "fmt"

func DefaultGenesis() *GenesisState {
	return &GenesisState{Params: DefaultParams(), Authorizations: []AuthorizationRecord{}}
}

func (gs GenesisState) Validate() error {
	if err := gs.Params.Validate(); err != nil {
		return err
	}
	seen := make(map[struct{ subject, msgType string }]struct{}, len(gs.Authorizations))
	for i, record := range gs.Authorizations {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("authorization %d: %w", i, err)
		}
		key := struct{ subject, msgType string }{record.Subject, record.MsgTypeUrl}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate authorization logical key (%s, %s)", key.subject, key.msgType)
		}
		seen[key] = struct{}{}
	}
	return nil
}
