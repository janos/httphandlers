package fileServer

import (
	"crypto/md5"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
)

type Server struct {
	root string
	dir  string

	options Options

	hashes map[string]string
	mu     sync.RWMutex
}

func New(root, dir string, options *Options) Server {
	if options == nil {
		options = &Options{}
	}
	return Server{
		root: root,
		dir:  dir,

		options: *options,

		hashes: map[string]string{},
		mu:     sync.RWMutex{},
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
		r.URL.Path = urlPath
	}
	p := path.Clean(urlPath)

	if s.root != "" {
		if p = strings.TrimPrefix(p, s.root); len(p) >= len(r.URL.Path) {
			s.HTTPError(w, r, errNotFound)
			return
		}
	}

	if s.options.IndexPage != "" && strings.HasSuffix(r.URL.Path, s.options.IndexPage) {
		redirect(w, r, "./")
		return
	}

	if (s.options.Hashed && !s.options.NoHashQueryStrings) ||
		(s.options.Hashed && s.options.NoHashQueryStrings && len(r.URL.RawQuery) == 0) {
		cPath := canonicalPath(p)
		h, err := s.getHash(cPath)
		if err != errNotRegularFile { // continue as usual if it is not a regular file
			if err != nil {
				s.HTTPError(w, r, err)
				return
			}
			if hPath := hashedPath(cPath, h); hPath != p {
				redirect(w, r, path.Join(s.root, hPath))
				return
			}
			if s.options.RedirectTrailingSlash && urlPath[len(urlPath)-1] == '/' {
				redirect(w, r, path.Join(s.root, p))
				return
			}
			p = cPath
			r.URL.Path = path.Join(s.root, cPath)
		}
	}

	f, err := open(s.dir, p)
	if err != nil {
		s.HTTPError(w, r, err)
		return
	}
	defer f.Close()

	d, err := f.Stat()
	if err != nil {
		s.HTTPError(w, r, err)
		return
	}

	if s.options.RedirectTrailingSlash {
		url := r.URL.Path
		if d.IsDir() {
			if url[len(url)-1] != '/' {
				redirect(w, r, url+"/")
				return
			}
		} else {
			if url[len(url)-1] == '/' {
				redirect(w, r, "../"+path.Base(url))
				return
			}
		}
	}

	if d.IsDir() {
		index := strings.TrimSuffix(p, "/") + s.options.IndexPage
		ff, err := open(s.dir, index)
		if err == nil {
			defer ff.Close()
			dd, err := ff.Stat()
			if err == nil {
				p = index
				d = dd
				f = ff
			}
		}
	}

	if d.IsDir() {
		s.HTTPError(w, r, errNotFound)
		return
	}

	http.ServeContent(w, r, d.Name(), d.ModTime(), f)
}

func (s *Server) HashedPath(p string) (string, error) {
	if !s.options.Hashed {
		return p, nil
	}
	h, err := s.getHash(p)
	if err != nil {
		return "", err
	}
	return path.Join(s.root, hashedPath(p, h)), nil
}

func (s Server) HTTPError(w http.ResponseWriter, r *http.Request, err error) {
	if os.IsNotExist(err) || err == errNotFound {
		if s.options.NotFoundHandler != nil {
			s.options.NotFoundHandler.ServeHTTP(w, r)
			return
		}
		DefaultNotFoundHandler.ServeHTTP(w, r)
		return
	}
	if os.IsPermission(err) {
		if s.options.ForbiddenHandler != nil {
			s.options.ForbiddenHandler.ServeHTTP(w, r)
			return
		}
		DefaultForbiddenHandler.ServeHTTP(w, r)
		return
	}
	if s.options.InternalServerErrorHandler != nil {
		s.options.InternalServerErrorHandler.ServeHTTP(w, r)
		return
	}
	DefaultInternalServerErrorhandler.ServeHTTP(w, r)
}

func (s *Server) getHash(p string) (h string, err error) {
	s.mu.RLock()
	h, ok := s.hashes[p]
	s.mu.RUnlock()
	if ok {
		return
	}

	f, err := open(s.dir, p)
	if err != nil {
		return
	}
	defer f.Close()

	d, err := f.Stat()
	if err != nil {
		return
	}
	if !d.Mode().IsRegular() {
		err = errNotRegularFile
		return
	}

	hash := md5.New()
	if _, err = io.Copy(hash, f); err != nil {
		return
	}
	h = makeHash(strings.TrimRight(base32Encoding.EncodeToString(hash.Sum(nil)), "="))
	s.mu.Lock()
	s.hashes[p] = h
	s.mu.Unlock()
	return
}
