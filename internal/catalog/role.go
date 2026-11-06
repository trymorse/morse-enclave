package catalog

import (
	"fmt"

	"morse/backend/internal/enum"
)

// Role says whether an endpoint may be the home of a conversation. A backup serves a turn only when no main endpoint of
// its tier can, or as a canary home.
type Role uint8

const (
	RoleMain Role = iota
	RoleBackup
)

var roleNames = enum.Names[Role]{RoleMain: "main", RoleBackup: "backup"}

func ParseRole(name string) (Role, error) {
	r, ok := roleNames.Parse(name)
	if !ok {
		return 0, fmt.Errorf("role %q must be one of %s; leave it out for %s", name, roleNames.List(), RoleMain)
	}
	return r, nil
}

func (r Role) String() string { return roleNames.String(r) }

func (r Role) MarshalText() ([]byte, error) { return roleNames.MarshalText(r) }
