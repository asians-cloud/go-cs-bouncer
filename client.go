package csbouncer

import (
        "context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
        qs "github.com/google/go-querystring/query"

	"github.com/asians-cloud/crowdsec/pkg/apiclient"
        "github.com/hashicorp/go-retryablehttp"
)

type Client struct {
  URL         string
  APIKey      string
  UserAgent   string
  maxBufferSize int
}

func (c *Client) addQueryParamsToURL(url string, opts apiclient.DecisionsStreamOpts) (string, error) {
    params, err := qs.Values(opts)
    if err != nil {
            return "", err
    }
    return fmt.Sprintf("%s?%s", url, params.Encode()), nil
}

func (c *Client) StreamDecisionConnect(ctx context.Context, opts apiclient.DecisionsStreamOpts) (*http.Response, error) {
  url, err := c.addQueryParamsToURL(c.URL + "v1/decisions-stream", opts)
  if err != nil {
    return nil, err
  }

  req, err := http.NewRequest(http.MethodGet, url, nil)
  if err != nil {
    return nil, err
  }
  
  req.Header.Set("Cache-Control", "no-cache")
  req.Header.Set("Accept", "text/event-stream")
  req.Header.Set("Connection", "keep-alive")
  req.Header.Set("X-Api-Key", c.APIKey)
  req.Header.Set("User-Agent", c.UserAgent)
  req.Header.Set("Content-Type", "application/json")
  
  retryClient := retryablehttp.NewClient()
  retryClient.RetryMax = 10
  standardClient := retryClient.StandardClient()
  resp, err := standardClient.Do(req)
  if err != nil {
    return nil, err
  }

  return resp, nil
}

func getApiClient(urlstr string, userAgent string, apiKey string, caPath string, certPath string, keyPath string, skipVerify *bool, logger logrus.FieldLogger) (*apiclient.ApiClient, error) {
	var (
		caCertPool *x509.CertPool
		client     *http.Client
	)

	if apiKey == "" && certPath == "" && keyPath == "" {
		return nil, errors.New("no API key nor certificate provided")
	}

	insecureSkipVerify := false

	apiURL, err := url.Parse(urlstr)
	if err != nil {
		return nil, fmt.Errorf("local API Url '%s': %w", urlstr, err)
	}

	if skipVerify != nil && *skipVerify {
		insecureSkipVerify = true
	}

	caCertPool, err = getCertPool(caPath, logger)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		var transport *apiclient.APIKeyTransport
		logger.Infof("Using API key auth")
		if apiURL.Scheme == "https" {
			transport = &apiclient.APIKeyTransport{
				APIKey: apiKey,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:            caCertPool,
						InsecureSkipVerify: insecureSkipVerify,
					},
				},
			}
		} else {
			transport = &apiclient.APIKeyTransport{
				APIKey: apiKey,
			}
		}
		client = transport.Client()
	}

	if certPath != "" && keyPath != "" {
		var certificate tls.Certificate

		logger.Infof("Using cert auth with cert '%s' and key '%s'", certPath, keyPath)
		certificate, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to load certificate '%s' and key '%s': %w", certPath, keyPath, err)
		}

		client = &http.Client{}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{certificate},
				InsecureSkipVerify: insecureSkipVerify,
			},
		}
	}

	return apiclient.NewDefaultClient(apiURL, "v1", userAgent, client)
}
