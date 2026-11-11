package cli

import (
	"regexp"

	"github.com/sofmon/farcast/datasphere"
)

// keyLossLine matches the mandated key-loss sentence on a line of its own. A
// plain Contains cannot see the defect the 2026-11-10 walk found: the sentence,
// which starts lowercase, run on after another one mid-line.
var keyLossLine = regexp.MustCompile(`(?m)^WARNING: ` + regexp.QuoteMeta(datasphere.KeyLossWarning) + `$`)
