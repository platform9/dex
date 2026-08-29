package httpclient_test

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dexidp/dex/pkg/httpclient"
)

func TestRootCAs(t *testing.T) {
	ts, caCertPEM, err := NewLocalHTTPSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello, client")
	}))
	assert.Nil(t, err)
	defer ts.Close()

	runTest := func(name string, certs []string) {
		t.Run(name, func(t *testing.T) {
			rootCAs := certs
			testClient, err := httpclient.NewHTTPClient(rootCAs, false)
			assert.Nil(t, err)

			res, err := testClient.Get(ts.URL)
			assert.Nil(t, err)

			if res != nil {
				greeting, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.Nil(t, err)

				assert.Equal(t, "Hello, client", string(greeting))
			}
		})
	}

	runTest("From runtime generated cert", []string{string(caCertPEM)})

	contentStr := base64.StdEncoding.EncodeToString(caCertPEM)
	runTest("From bytes", []string{contentStr})
}

func TestInsecureSkipVerify(t *testing.T) {
	ts, _, err := NewLocalHTTPSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello, client")
	}))
	assert.Nil(t, err)
	defer ts.Close()

	insecureSkipVerify := true

	testClient, err := httpclient.NewHTTPClient(nil, insecureSkipVerify)
	assert.Nil(t, err)

	res, err := testClient.Get(ts.URL)
	assert.Nil(t, err)

	if res != nil {
		greeting, err := io.ReadAll(res.Body)
		res.Body.Close()
		assert.Nil(t, err)

		assert.Equal(t, "Hello, client", string(greeting))
	}
}

func NewLocalHTTPSTestServer(handler http.Handler) (*httptest.Server, []byte, error) {
	ts := httptest.NewUnstartedServer(handler)

	// Generate CA and server cert/key once so client and server share trust
	caCertPEM, serverCertPEM, serverKeyPEM, err := httpclient.GenerateTestCertificates()
	if err != nil {
		return nil, nil, err
	}

	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, nil, err
	}

	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	return ts, caCertPEM, nil
}
