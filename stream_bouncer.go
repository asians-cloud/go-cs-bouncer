package csbouncer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/asians-cloud/crowdsec/pkg/apiclient"
	"github.com/asians-cloud/crowdsec/pkg/models"
)

var TotalLAPIError prometheus.Counter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "lapi_requests_failures_total",
	Help: "The total number of failed calls to CrowdSec LAPI",
},
)

var TotalLAPICalls prometheus.Counter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "lapi_requests_total",
	Help: "The total number of calls to CrowdSec LAPI",
},
)

type StreamBouncer struct {
	APIKey             string `yaml:"api_key"`
	APIUrl             string `yaml:"api_url"`
	InsecureSkipVerify *bool  `yaml:"insecure_skip_verify"`
	CertPath           string `yaml:"cert_path"`
	KeyPath            string `yaml:"key_path"`
	CAPath             string `yaml:"ca_cert_path"`

	TickerInterval         string   `yaml:"update_frequency"`
	Scopes                 []string `yaml:"scopes"`
	ScenariosContaining    []string `yaml:"scenarios_containing"`
	ScenariosNotContaining []string `yaml:"scenarios_not_containing"`
	Origins                []string `yaml:"origins"`
	Startup                bool     `yaml:"startup"`

	TickerIntervalDuration time.Duration
	Stream                 chan *models.DecisionsStreamResponse
	APIClient              *apiclient.ApiClient
	UserAgent              string
	Opts                   apiclient.DecisionsStreamOpts
}

// Config() fills the struct with configuration values from a file. It is not
// aware of .yaml.local files so it is recommended to use ConfigReader() instead.
func (b *StreamBouncer) Config(configPath string) error {
	reader, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file '%s': %w", configPath, err)
	}

	return b.ConfigReader(reader)
}

func (b *StreamBouncer) ConfigReader(configReader io.Reader) error {
	content, err := io.ReadAll(configReader)
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}

	err = yaml.Unmarshal(content, b)
	if err != nil {
		return fmt.Errorf("unable to unmarshal config file: %w", err)
	}

	return nil
}

func (b *StreamBouncer) Init() error {
	var err error

	// validate the configuration

	if b.APIUrl == "" {
		return fmt.Errorf("config does not contain LAPI url")
	}

	if !strings.HasSuffix(b.APIUrl, "/") {
		b.APIUrl += "/"
	}

	if b.APIKey == "" && b.CertPath == "" && b.KeyPath == "" {
		return fmt.Errorf("config does not contain LAPI key or certificate")
	}

	//  scopes, origins, etc.

	if b.Scopes != nil {
		b.Opts.Scopes = strings.Join(b.Scopes, ",")
	}

	if b.ScenariosContaining != nil {
		b.Opts.ScenariosContaining = strings.Join(b.ScenariosContaining, ",")
	}

	if b.ScenariosNotContaining != nil {
		b.Opts.ScenariosNotContaining = strings.Join(b.ScenariosNotContaining, ",")
	}

	if b.Origins != nil {
		b.Opts.Origins = strings.Join(b.Origins, ",")
	}

	// update_frequency or however it's called in the .yaml of the specific bouncer

	if b.TickerInterval == "" {
		log.Warningf("lapi update interval is not defined, using default value of 10s")
		b.TickerInterval = "10s"
	}

	b.TickerIntervalDuration, err = time.ParseDuration(b.TickerInterval)
	if err != nil {
		return fmt.Errorf("unable to parse lapi update interval '%s': %w", b.TickerInterval, err)
	}

	if b.TickerIntervalDuration <= 0 {
		return fmt.Errorf("lapi update interval must be positive")
	}

	// prepare the client object for the lapi

	b.Stream = make(chan *models.DecisionsStreamResponse)

	b.APIClient, err = getApiClient(b.APIUrl, b.UserAgent, b.APIKey, b.CAPath, b.CertPath, b.KeyPath, b.InsecureSkipVerify, log.StandardLogger())
	if err != nil {
		return fmt.Errorf("api client init: %w", err)
	}
	return nil
}

func (b *StreamBouncer) Run(ctx context.Context) {
	ticker := time.NewTicker(b.TickerIntervalDuration)

	b.Opts.Startup = b.Startup

	getDecisionStream := func() (*models.DecisionsStreamResponse, *apiclient.Response, error) {
		data, resp, err := b.APIClient.Decisions.GetStream(context.Background(), b.Opts)
		TotalLAPICalls.Inc()
		if err != nil {
			TotalLAPIError.Inc()
		}
		return data, resp, err
	}

	data, resp, err := getDecisionStream()

	if resp != nil && resp.Response != nil {
		resp.Response.Body.Close()
	}

	if err != nil {
		log.Error(err)
		// close the stream
		// this may cause the bouncer to exit
		close(b.Stream)
		return
	}

	b.Stream <- data
	b.Opts.Startup = false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			data, resp, err := getDecisionStream()
			if err != nil {
				if resp != nil && resp.Response != nil {
					resp.Response.Body.Close()
				}
				log.Errorf(err.Error())
				continue
			}
			if resp != nil && resp.Response != nil {
				resp.Response.Body.Close()
			}
			b.Stream <- data
		}
	}
}

func (b *StreamBouncer) RunStream(ctx context.Context) {
	getDecoder := func(ctx context.Context) (*json.Decoder, error) {
		resp, err := b.APIClient.Decisions.StreamDecisions(ctx, b.Opts)
		TotalLAPICalls.Inc()
		if err != nil {
			TotalLAPIError.Inc()
                        return nil, err
		}
                defer resp.Response.Body.Close()
      
                log.Info(resp)
                log.Info(resp.Response)
                log.Info(resp.Response.Body)
                decoder := json.NewDecoder(resp.Response.Body)
		return decoder, err
	}

	decoder, err := getDecoder(ctx)

	if err != nil {
		log.Error(err)
		// close the stream
		// this may cause the bouncer to exit
		close(b.Stream)
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
                        data := &models.DecisionsStreamResponse{
                          New: []*models.Decision{}, 
                          Deleted: []*models.Decision{},
                        }

			// Decode each JSON object
			if err := decoder.Decode(data); err != nil {
				log.Error("Error decoding JSON:", err)
                                decoder , err = getDecoder(ctx)
                                if err != nil {
                                  log.Error(err)
                                  close(b.Stream)
                                  return
                                }
				continue
			}

                        log.Info("Recieved data: ", data)
                        
			b.Stream <- data
		}
	}
}
