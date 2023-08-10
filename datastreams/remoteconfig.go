// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package datastreams

import (
	"encoding/json"
	"fmt"
	rc "github.com/DataDog/datadog-agent/pkg/remoteconfig/state"
	"github.com/davecgh/go-spew/spew"
	"gopkg.in/DataDog/dd-trace-go.v1/internal/log"
	"gopkg.in/DataDog/dd-trace-go.v1/internal/remoteconfig"
)

const DATA_STREAMS_PRODUCT = "DEBUG"

func genApplyStatus(ack bool, err error) rc.ApplyStatus {
	status := rc.ApplyStatus{
		State: rc.ApplyStateUnacknowledged,
	}
	if err != nil {
		status.State = rc.ApplyStateError
		status.Error = err.Error()
	} else if ack {
		status.State = rc.ApplyStateAcknowledged
	}

	return status
}

func statusesFromUpdate(u remoteconfig.ProductUpdate, ack bool, err error) map[string]rc.ApplyStatus {
	statuses := make(map[string]rc.ApplyStatus, len(u))
	for path := range u {
		statuses[path] = genApplyStatus(ack, err)
	}
	return statuses
}

type DSMFeaturesData struct {
	// todo[piochelepiotr] should probably be debug here.
	DSM struct {
		PublicKey string `json:"public_key"`
	} `json:"dsm"`
}

// enablePayloadSampling is the RC callback called when an update is received for DATA_STREAMS
func (p *Processor) enablePayloadSampling(updates map[string]remoteconfig.ProductUpdate) map[string]rc.ApplyStatus {
	if u, ok := updates[DATA_STREAMS_PRODUCT]; ok {
		fmt.Println("have updates for data streams!")
		spew.Dump(u)
		statuses := statusesFromUpdate(u, false, nil)
		for path, raw := range u {
			fmt.Printf("for path %s, getting data %s", path, string(raw))
			log.Debug("data_streams: Remote config: processing %s", path)

			// A nil config means DSM was disabled, and we stopped receiving the config file
			// Don't ack the config in this case and return early
			if raw == nil {
				log.Debug("data_streams: nil remote config")
				p.removeSampleConfig(path)
				statuses[path] = rc.ApplyStatus{State: rc.ApplyStateAcknowledged}
				continue
			}
			var data DSMFeaturesData
			var err error
			if err = json.Unmarshal(raw, &data); err != nil {
				log.Error("data_streams: Remote config: error while unmarshalling %s: %v. Configuration won't be applied.", path, err)
			}
			fmt.Println(string(raw))
			fmt.Println("Received a new update :)")
			spew.Dump(data)
			if data.DSM.PublicKey != "" {
				// todo[piochelepiotr] probably we will need to encode the key in the json?
				p.addSampleConfig(path, data.DSM.PublicKey)
			}
			if err != nil {
				statuses[path] = genApplyStatus(false, err)
			} else {
				statuses[path] = rc.ApplyStatus{State: rc.ApplyStateAcknowledged}
			}
		}
	}
	return map[string]rc.ApplyStatus{}
}

func (p *Processor) stopRemoteConfig() {
	if p.rc != nil {
		p.rc.Stop()
	}
}

func (p *Processor) enableRemoteActivation() {
	p.rc.RegisterProduct(DATA_STREAMS_PRODUCT)
	p.rc.RegisterCallback(p.enablePayloadSampling)
}

func (p *Processor) startRemoteConfig(config remoteconfig.ClientConfig) {
	client, err := remoteconfig.NewClient(config)
	fmt.Println("starting!")
	log.Info("starting remote config!")
	if err != nil {
		log.Error("data_streams: Remote config: disabled due to a client creation error: %v", err)
		return
	}
	p.rc = client
	p.enableRemoteActivation()
	p.rc.Start()
}