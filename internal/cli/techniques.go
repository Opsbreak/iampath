package cli

import (
	"encoding/json"
	"io"

	"github.com/Opsbreak/iampath/internal/escalation"
)

type techniqueJSON struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Category     string   `json:"category"`
	Permissions  []string `json:"requiredPermissions"`
	Service      string   `json:"passedToService,omitempty"`
	Inventory    string   `json:"requiresInput,omitempty"`
	Description  string   `json:"description"`
	Exploitation string   `json:"exploitation"`
	Remediation  string   `json:"remediation"`
	Weight       int      `json:"weight"`
}

func writeTechniquesJSON(w io.Writer, ts []*escalation.Technique) error {
	out := make([]techniqueJSON, 0, len(ts))
	for _, t := range ts {
		out = append(out, techniqueJSON{
			ID: t.ID, Name: t.Name, Category: string(t.Category), Permissions: t.Permissions,
			Service: t.Service, Inventory: t.Inventory, Description: t.Description,
			Exploitation: t.Exploitation, Remediation: t.Remediation, Weight: t.Weight,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
