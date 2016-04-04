package basicAuth

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"

	"golang.org/x/crypto/scrypt"
)

type Auth struct {
	Handler             http.Handler
	UnauthorizedHandler http.Handler
	Realm               string
	Users               map[string]string
	AllowedCIDRs        []string
	Salt                []byte
}

func (h Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.UnauthorizedHandler == nil {
		h.UnauthorizedHandler = http.HandlerFunc(defaultBasicAuthUnauthorizedHandler)
	}

	authenticated, err := h.authenticate(r)
	if err != nil {
		panic(err)
	}
	if authenticated == false {
		h.unauthorized(w, r)
		return
	}

	h.Handler.ServeHTTP(w, r)
}

func (h Auth) authenticate(r *http.Request) (authenticated bool, err error) {
	var host string
	host, _, err = net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	var cidrnet *net.IPNet
	for _, cidr := range h.AllowedCIDRs {
		_, cidrnet, err = net.ParseCIDR(cidr)
		if err != nil {
			return
		}
		if cidrnet.Contains(ip) {
			authenticated = true
			return
		}
	}

	const scheme string = "Basic "

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, scheme) {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(scheme):])
	if err != nil {
		return
	}

	creds := bytes.SplitN(decoded, []byte(":"), 2)
	if len(creds) != 2 {
		return
	}

	passwd, ok := h.Users[string(creds[0])]
	if !ok {
		return
	}
	if passwd == "" {
		return
	}
	if strings.HasPrefix(passwd, "{SHA1}") {
		d := sha1.New()
		d.Write([]byte(creds[1]))
		if passwd[5:] == base64.StdEncoding.EncodeToString(d.Sum(nil)) {
			authenticated = true
			return
		}
	}
	if strings.HasPrefix(passwd, "{scrypt}") {
		var dk []byte
		dk, err = scrypt.Key([]byte(creds[1]), h.Salt, 16384, 8, 1, 32)
		if err != nil {
			err = fmt.Errorf("scrypt hashing: %s", err)
			return
		}
		if passwd[8:] == base64.StdEncoding.EncodeToString(dk) {
			authenticated = true
			return
		}
	}

	return
}

func (h Auth) unauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", h.Realm))
	h.UnauthorizedHandler.ServeHTTP(w, r)
}

func defaultBasicAuthUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
