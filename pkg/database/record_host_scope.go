package database

// RecordMatchesHostScopes is the in-memory counterpart of applyHostScopeFilter.
// It compares stored destination columns exactly, never the attribution URL or
// request Host header. Empty scopes do not constrain the origin; an empty scheme
// or zero port leaves just that field unconstrained, matching the SQL predicate.
func RecordMatchesHostScopes(record *HTTPRecord, hosts []HostTarget) bool {
	if record == nil {
		return false
	}
	if len(hosts) == 0 {
		return true
	}
	for _, host := range hosts {
		if record.Hostname == host.Hostname && (host.Scheme == "" || record.Scheme == host.Scheme) &&
			(host.Port == 0 || record.Port == host.Port) {
			return true
		}
	}
	return false
}
