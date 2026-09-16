package types

func DefaultParams() Params { return Params{} }

func (Params) Validate() error { return nil }
