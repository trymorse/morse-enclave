package routes

func (rt Route) SendsKeySettings() bool {
	switch up := rt.Upstream.(type) {
	case Attested:
		return !rt.Tier.Sealed() && attestedCapability(up.Attester).sendsSettings
	case Vendor:
		c := capabilities[up.Provider]
		return c.openAIHost || c.sendsSettings
	}
	return false
}
