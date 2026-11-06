package catalog

type Named struct {
	Name  string
	Model ModelID
	Tier  Tier
	Order int
}

func IDNames(routes []Named) map[string]string {
	best := map[ModelID]Named{}
	taken := map[string]bool{}
	for _, r := range routes {
		taken[r.Name] = true
		if b, seen := best[r.Model]; !seen || r.Tier > b.Tier || r.Tier == b.Tier && r.Order < b.Order {
			best[r.Model] = r
		}
	}
	names := map[string]string{}
	for id, r := range best {
		if !taken[string(id)] {
			names[string(id)] = r.Name
		}
	}
	return names
}
