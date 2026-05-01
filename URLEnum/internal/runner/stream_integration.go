package runner

import (
	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/output"
)

func attachStream(store *resultStore, outPath string) (*output.StreamWriter, error) {
	if outPath == "" {
		return nil, nil
	}

	sw, err := output.NewStreamWriter(outPath, 8192)
	if err != nil {
		return nil, err
	}

	// wrap Add to stream results immediately
	origAdd := store.Add
	store.Add = func(raw, source string) bool {
		added := origAdd(raw, source)
		if added && sw != nil {
			sw.Write(raw)
		}
		return added
	}

	return sw, nil
}
