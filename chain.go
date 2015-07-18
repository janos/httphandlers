package httphandlers // import "resenje.org/httphandlers"

import "net/http"

func ChainHandlers(finalHandler http.Handler, handlers ...func(http.Handler) http.Handler) (handler http.Handler) {
	if finalHandler == nil {
		finalHandler = http.DefaultServeMux
	}
	handler = finalHandler
	for i := len(handlers) - 1; i >= 0; i-- {
		handler = handlers[i](handler)
	}
	return
}
