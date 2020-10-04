# Go CrowdSec Bouncer

`go-cs-bouncer` is a golang library for communicating with CrowdSec API.

## Installation

To install `go-cs-bouncer` package, you need to install Go and set your Go workspace first.

1. You can use the below Go command to install `go-cs-bouncer`:

```sh
$ go get -u github.com/crowdsecurity/go-cs-bouncer
```

2. Import it in your code:

```go
import "github.com/crowdsecurity/go-cs-bouncer"
```

## Quick Start

 
```sh
# assume the following codes in main.go file
$ cat main.go
```

```go
package main

import "github.com/crowdsecurity/go-cs-bouncer"

func main() {

	bouncer := &Bouncer{
		APIKey:         "ebd4db481d51525fd0df924a69193921",
		APIUrl:         "http://localhost:8080/",
		TickerInterval: "2m",
	}

	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go bouncer.Run()

	for {
		select {
		case decision := <-bouncer.NewDecision:
			// Do some stuff with new decisions
			fmt.Printf("new decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		case decision := <-bouncer.ExpiredDecision:
			// do some stuff with expired decisions
			fmt.Printf("old decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		}
	}
}
```

```sh
# run main.go
$ go run main.go
```


## Decision object

The decision objet correspond to the following structure:

```go
type Decision struct {

	// duration
	Duration *string `json:"duration"`

	EndIP int64 `json:"end_ip,omitempty"`

	ID int64 `json:"id,omitempty"`

	// the origin of the decision : cscli, crowdsec
	Origin *string `json:"origin"`

	// scenario
	Scenario *string `json:"scenario"`

	// the scope of decision : does it apply to an IP, a range, a username, etc
	Scope *string `json:"scope"`

	StartIP int64 `json:"start_ip,omitempty"`

	// the type of decision, might be 'ban', 'captcha' or something custom. Ignored when watcher (cscli/crowdsec) is pushing to APIL.
	Type *string `json:"type"`

	// the value of the decision scope : an IP, a range, a username, etc
	Value *string `json:"value"`
}
```



