package httpDigestAuth

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type myjar struct {
	jar map[string][]*http.Cookie
}

// DigestHeaders tracks the state of authentication
type DigestHeaders struct {
	Realm     string
	Qop       string
	Method    string
	Nonce     string
	Opaque    string
	Algorithm string
	HA1       string
	HA2       string
	Cnonce    string
	Path      string
	Nc        int16
	Username  string
	Password  string
}

// SetCookies saves cookies for a specific host in the jar
func (p *myjar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	p.jar[u.Host] = cookies
}

// Cookies returns all cookies from jar
func (p *myjar) Cookies(u *url.URL) []*http.Cookie {
	return p.jar[u.Host]
}

func (d *DigestHeaders) digestChecksum() {

	// check algorithm to use
	switch d.Algorithm {
	case "MD5":
		// HA1=MD5(username:realm:password)
		d.HA1 = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", d.Username, d.Realm, d.Password))))

	case "MD5-sess":
		// HA1=MD5(MD5(username:realm:password):nonce:cnonce)
		d.HA1 = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%x:%s:%s", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s",
			d.Username, d.Realm, d.Password))), d.Nonce, d.Cnonce))))

	}

	d.HA2 = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s", d.Method, d.Path))))

}

// ApplyAuth adds proper auth header to the passed request
func (d *DigestHeaders) ApplyAuth(req *http.Request) {
	d.Nc += 0x1
	d.Cnonce = randomKey()
	d.Method = req.Method
	d.Path = req.URL.RequestURI()
	d.digestChecksum()

	response := fmt.Sprintf("%x", md5.Sum([]byte(strings.Join([]string{d.HA1, d.Nonce, fmt.Sprintf("%08x", d.Nc),
		d.Cnonce, d.Qop, d.HA2}, ":"))))

	AuthHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc=%08x, qop=%s, response="%s", algorithm=%s`,
		d.Username, d.Realm, d.Nonce, d.Path, d.Cnonce, d.Nc, d.Qop, response, d.Algorithm)
	if d.Opaque != "" {
		AuthHeader = fmt.Sprintf(`%s, opaque="%s"`, AuthHeader, d.Opaque)
	}

	req.Header.Set("Authorization", AuthHeader)
}

// Auth authenticates against a given URI
func (d *DigestHeaders) Auth(username string, password string, uri string) (*DigestHeaders, error) {

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 10,
			DisableCompression:  true,
		},
		Timeout: time.Duration(10 * time.Second),
		Jar:     &myjar{jar: make(map[string][]*http.Cookie)},
	}

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return d, fmt.Errorf("error in auth package: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return d, fmt.Errorf("error in auth package: %v", err)
	}

	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {

		authn := digestAuthParams(resp)
		algorithm := authn["algorithm"]
		d := &DigestHeaders{}
		u, _ := url.Parse(uri)
		d.Path = u.RequestURI()
		d.Realm = authn["realm"]
		d.Qop = authn["qop"]
		d.Nonce = authn["nonce"]
		d.Opaque = authn["opaque"]
		if algorithm == "" {
			d.Algorithm = "MD5"
		} else {
			d.Algorithm = authn["algorithm"]
		}
		d.Nc = 0x0
		d.Username = username
		d.Password = password

		req, err = http.NewRequest("GET", uri, nil)
		d.ApplyAuth(req)

		resp, err = client.Do(req)
		if err != nil {
			return d, fmt.Errorf("error in auth package: %v", err)
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			d = &DigestHeaders{}
			err = fmt.Errorf("response status code was %v", resp.StatusCode)
		}
		return d, err

	} else if resp.StatusCode == http.StatusOK {
		return nil, nil
	}

	return nil, fmt.Errorf("response status code should have been 401, it was %v", resp.StatusCode)
}

/*
Parse Authorization header from the http.Request. Returns a map of
auth parameters or nil if the header is not a valid parsable Digest
auth header.
*/
func digestAuthParams(r *http.Response) map[string]string {
	s := strings.SplitN(r.Header.Get("Www-Authenticate"), " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	result := map[string]string{}
	for _, kv := range strings.Split(s[1], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.Trim(parts[0], "\" ")] = strings.Trim(parts[1], "\" ")
	}
	return result
}

func randomKey() string {
	k := make([]byte, 12)
	for bytes := 0; bytes < len(k); {
		if n, err := rand.Read(k[bytes:]); err == nil {
			bytes += n
		}
	}
	return base64.StdEncoding.EncodeToString(k)
}
