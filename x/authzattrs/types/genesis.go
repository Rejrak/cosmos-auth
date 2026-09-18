package types

import "fmt"

func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Params:              DefaultParams(),
		Authorizations:      []AuthorizationRecord{},
		IssuerSets:          []IssuerSet{},
		Issuers:             []Issuer{},
		CurrentIssuerSets:   []CurrentIssuerSetSelection{},
		LastAppliedBatchIds: []LastAppliedBatchID{},
	}
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

	issuerSets := make(map[uint64]IssuerSet, len(gs.IssuerSets))
	for i, issuerSet := range gs.IssuerSets {
		if err := issuerSet.Validate(); err != nil {
			return fmt.Errorf("issuer set %d: %w", i, err)
		}
		if _, exists := issuerSets[issuerSet.IssuerSetId]; exists {
			return fmt.Errorf("duplicate issuer_set_id %d", issuerSet.IssuerSetId)
		}
		issuerSets[issuerSet.IssuerSetId] = issuerSet
	}

	issuerKeys := make(map[struct {
		issuerSetID uint64
		issuerID    string
	}]struct{}, len(gs.Issuers))
	for i, issuer := range gs.Issuers {
		if err := issuer.Validate(); err != nil {
			return fmt.Errorf("issuer %d: %w", i, err)
		}
		key := struct {
			issuerSetID uint64
			issuerID    string
		}{issuer.IssuerSetId, issuer.IssuerId}
		if _, exists := issuerKeys[key]; exists {
			return fmt.Errorf("duplicate issuer key (%d, %s)", key.issuerSetID, key.issuerID)
		}
		if _, exists := issuerSets[issuer.IssuerSetId]; !exists {
			return fmt.Errorf("issuer %d references missing issuer set %d", i, issuer.IssuerSetId)
		}
		issuerKeys[key] = struct{}{}
	}

	selectionKeys := make(map[struct{ policyID, msgTypeURL string }]struct{}, len(gs.CurrentIssuerSets))
	for i, selection := range gs.CurrentIssuerSets {
		if selection.PolicyId == "" {
			return fmt.Errorf("current issuer set selection %d: policy_id is empty", i)
		}
		if selection.MsgTypeUrl != MsgSendTypeURL {
			return fmt.Errorf("current issuer set selection %d: unsupported msg_type_url %q", i, selection.MsgTypeUrl)
		}
		if selection.IssuerSetId == 0 {
			return fmt.Errorf("current issuer set selection %d: issuer_set_id must be positive", i)
		}
		key := struct{ policyID, msgTypeURL string }{selection.PolicyId, selection.MsgTypeUrl}
		if _, exists := selectionKeys[key]; exists {
			return fmt.Errorf("duplicate current issuer set selection (%s, %s)", key.policyID, key.msgTypeURL)
		}
		issuerSet, exists := issuerSets[selection.IssuerSetId]
		if !exists {
			return fmt.Errorf("current issuer set selection %d references missing issuer set %d", i, selection.IssuerSetId)
		}
		if !issuerSet.Active {
			return fmt.Errorf("current issuer set selection %d references inactive issuer set %d", i, selection.IssuerSetId)
		}
		if issuerSet.PolicyId != selection.PolicyId || issuerSet.MsgTypeUrl != selection.MsgTypeUrl {
			return fmt.Errorf("current issuer set selection %d policy or message scope mismatch", i)
		}
		selectionKeys[key] = struct{}{}
	}

	replayIssuerSets := make(map[uint64]struct{}, len(gs.LastAppliedBatchIds))
	for i, replay := range gs.LastAppliedBatchIds {
		if replay.IssuerSetId == 0 || replay.BatchId == 0 {
			return fmt.Errorf("last applied batch ID %d: issuer_set_id and batch_id must be positive", i)
		}
		if _, exists := replayIssuerSets[replay.IssuerSetId]; exists {
			return fmt.Errorf("duplicate last applied batch ID for issuer set %d", replay.IssuerSetId)
		}
		if _, exists := issuerSets[replay.IssuerSetId]; !exists {
			return fmt.Errorf("last applied batch ID %d references missing issuer set %d", i, replay.IssuerSetId)
		}
		replayIssuerSets[replay.IssuerSetId] = struct{}{}
	}
	return nil
}
