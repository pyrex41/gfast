package gfast

import (
	"context"
	"fmt"
)

// Background runs fn after the response is written and before request-scoped
// values that implement io.Closer are closed. fn is not cancelled when the
// client disconnects. There is no queue and no retry.
func Background(ctx context.Context, fn func()) {
	if fn == nil {
		return
	}
	st, err := stateFrom(ctx)
	if err != nil {
		panic(fmt.Errorf("gfast.Background: %w", err))
	}
	st.tasks = append(st.tasks, fn)
}
