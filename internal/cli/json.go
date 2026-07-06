package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

// printJSON writes v as indented JSON with a trailing newline. Every
// --json output path goes through here so the shape stays uniform.
func printJSON(w io.Writer, v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", out)
	return err
}
