package httphandlers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const basicAuthScheme string = "Basic "

type KeyAuth struct {
	Handler             http.Handler
	UnauthorizedHandler http.Handler
	Keys                map[string]bool
	ValidateFunc        func(key string) bool
	AuthorizeAll        bool
	AuthorizedNetworks  []net.IPNet
	HeaderName          string
	BasicAuthRealm      string
}

func (h KeyAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.UnauthorizedHandler == nil {
		h.UnauthorizedHandler = http.HandlerFunc(defaultKeyAuthUnauthorizedHandler)
	}

	if h.authenticate(r) == false {
		h.unauthorized(w, r)
		return
	}

	h.Handler.ServeHTTP(w, r)
}

func (h KeyAuth) authenticate(r *http.Request) bool {
	if h.AuthorizeAll {
		return true
	}

	if len(h.AuthorizedNetworks) > 0 {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			panic(err)
		}
		ip := net.ParseIP(host)
		for _, network := range h.AuthorizedNetworks {
			if network.Contains(ip) {
				return true
			}
		}
	}

	if h.HeaderName != "" {
		key := r.Header.Get(h.HeaderName)
		if key != "" {
			if enabled, ok := h.Keys[key]; ok {
				return enabled
			}
			if h.ValidateFunc != nil {
				return h.ValidateFunc(key)
			}
		}
	}

	if h.BasicAuthRealm != "" {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, basicAuthScheme) {
			return false
		}

		decoded, err := base64.StdEncoding.DecodeString(auth[len(basicAuthScheme):])
		if err != nil {
			return false
		}

		creds := bytes.SplitN(decoded, []byte(":"), 2)
		if len(creds) != 2 {
			return false
		}

		key := string(creds[0])
		if key != "" {
			if enabled, ok := h.Keys[key]; ok {
				return enabled
			}
			if h.ValidateFunc != nil {
				return h.ValidateFunc(key)
			}
		}
	}

	return false
}

func (h KeyAuth) unauthorized(w http.ResponseWriter, r *http.Request) {
	if h.BasicAuthRealm != "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", h.BasicAuthRealm))
	}
	h.UnauthorizedHandler.ServeHTTP(w, r)
}

func defaultKeyAuthUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
