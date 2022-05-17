package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/sensiblecodeio/tiny-ssl-reverse-proxy/proxyprotocol"
)

// Version number
const Version = "0.22.0"

var message = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>
Backend Unavailable
</title>
<style>
body {
	font-family: fantasy;
	text-align: center;
	padding-top: 20%;
	background-color: #f1f6f8;
}
</style>
</head>
<body>
<h1>503 Backend Unavailable</h1>
<p>Sorry, we&lsquo;re having a brief problem. You can retry.</p>
<p>If the problem persists, please get in touch.</p>
</body>
</html>`

type ConnectionErrorHandler struct{ http.RoundTripper }

func (c *ConnectionErrorHandler) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.RoundTripper.RoundTrip(req)
	if err != nil {
		log.Printf("Error: backend request failed for %v: %v",
			req.RemoteAddr, err)
	}
	if _, ok := err.(*net.OpError); ok {
		r := &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       ioutil.NopCloser(bytes.NewBufferString(message)),
		}
		return r, nil
	}
	return resp, err
}

func tlsId(version string) uint16 {
	var tlsid uint16
	switch version {
	case "TLS10":
		tlsid = tls.VersionTLS10
	case "TLS11":
		tlsid = tls.VersionTLS11
	case "TLS12":
		tlsid = tls.VersionTLS12
	case "TLS13":
		tlsid = tls.VersionTLS13
	default:
		tlsid = tls.VersionTLS12
	}
	return tlsid
}

func main() {
	var (
		listen, cert, key, where, clientTLSversion   string
		useTLS, useLogging, behindTCPProxy, insecure bool
		flushInterval                                time.Duration
	)
	flag.StringVar(&listen, "listen", ":443", "Bind address to listen on")
	flag.StringVar(&key, "key", "/etc/ssl/private/key.pem", "Path to PEM key")
	flag.StringVar(&cert, "cert", "/etc/ssl/private/cert.pem", "Path to PEM certificate")
	flag.StringVar(&where, "where", "http://localhost:80", "Place to forward connections to")
	flag.BoolVar(&useTLS, "tls", true, "accept HTTPS connections")
	flag.BoolVar(&useLogging, "logging", true, "log requests")
	flag.BoolVar(&behindTCPProxy, "behind-tcp-proxy", false, "running behind TCP proxy (such as ELB or HAProxy)")
	flag.DurationVar(&flushInterval, "flush-interval", 0, "minimum duration between flushes to the client (default: off)")
	flag.BoolVar(&insecure, "insecure", false, "do not validate target certificate (default: false)")
	flag.StringVar(&clientTLSversion, "client-tls-ver", "TLS12", "tls version for client connections (default: TLS12)")
	oldUsage := flag.Usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\n%v version %v\n\n", os.Args[0], Version)
		oldUsage()
	}
	flag.Parse()

	targetUrl, err := url.Parse(where)
	if err != nil {
		log.Fatalln("Fatal parsing -where:", err)
	}

	httpProxy := httputil.NewSingleHostReverseProxy(targetUrl)

	httpProxy.Transport = &ConnectionErrorHandler{&http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tlsId(clientTLSversion),
			InsecureSkipVerify: insecure,
		}}}
	httpProxy.FlushInterval = flushInterval
	var handler http.Handler

	handler = httpProxy

	originalHandler := handler
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_version" {
			w.Header().Add("X-Tiny-SSL-Version", Version)
		}
		r.Header.Set("X-Forwarded-Proto", "https")
		originalHandler.ServeHTTP(w, r)
	})

	if useLogging {
		handler = &LoggingMiddleware{handler}
	}

	server := &http.Server{Addr: listen, Handler: handler}

	switch {
	case useTLS && behindTCPProxy:
		err = proxyprotocol.BehindTCPProxyListenAndServeTLS(server, cert, key)
	case behindTCPProxy:
		err = proxyprotocol.BehindTCPProxyListenAndServe(server)
	case useTLS:
		err = server.ListenAndServeTLS(cert, key)
	default:
		err = server.ListenAndServe()
	}

	log.Fatalln(err)
}
