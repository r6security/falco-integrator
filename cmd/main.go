/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	amtdv1beta1client "github.com/r6security/falco-integrator/clients"
	seceventclient "github.com/r6security/falco-integrator/clients/securityevent"
	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// DefaultPort is the default port to use if one is not specified by the SERVER_PORT environment variable
const DefaultPort = "33333"
const MAX_BODY_SIZE = 1048576

// The message structure from falco webhook
type Response struct {
	Time         time.Time            `json:"time,omitempty"`
	Priority     string               `json:"priority,omitempty"`
	Rule         string               `json:"rule,omitempty"`
	Output       string               `json:"output,omitempty"`
	Hostname     string               `json:"hostname,omitempty"`
	Source       string               `json:"source,omitempty"`
	Tags         []string             `json:"tags,omitempty"`
	OutputFields ResponseOutputFields `json:"output_fields,omitempty"`
}

type ResponseOutputFields struct {
	ContainerID    string `json:"container.id,omitempty"`
	ContainerImage string `json:"container.image.repository,omitempty"`
	EventFlags     string `json:"evt.arg.flags,omitempty"`
	//EventTime      time.Time `json:"evt.time,omitempty"`
	Namespace string `json:"k8s.ns.name,omitempty"`
	Pod       string `json:"k8s.pod.name,omitempty"`
}

func getServerPort() string {
	port := os.Getenv("SERVER_PORT")
	if port != "" {
		return port
	}

	return DefaultPort
}

type FalcoBackend struct {
	client *seceventclient.SecurityEventInterface
	ctx    context.Context
}

// Use the webhook feature in falco to get falco trigger messages.
// Assume the messages are in json formats.
func (fb FalcoBackend) FalcoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	r.Body = http.MaxBytesReader(w, r.Body, MAX_BODY_SIZE)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Cannot read body %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("{\"Cannot read request body\"}"))
		return
	}

	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("Cannot unmarshall %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("{\"Cannot parse request body\"}"))
		return
	}

	name := fmt.Sprintf("falco-%s-%d", response.OutputFields.Pod, response.Time.Unix())
	log.Printf("Creating secevent with name %s", name)
	c := *fb.client
	_, error := c.Create(fb.ctx, &amtdapi.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      make(map[string]string),
			Annotations: make(map[string]string),
			Name:        name,
			Namespace:   response.OutputFields.Namespace,
		},
		Spec: amtdapi.SecurityEventSpec{
			Targets:     []string{fmt.Sprintf("%s/%s", response.OutputFields.Namespace, response.OutputFields.Pod)},
			Description: response.Output,
			Rule: amtdapi.Rule{
				Type:        response.Rule,
				ThreatLevel: response.Priority,
				Source:      "FalcoIntegrator",
			},
		},
	})

	if error != nil {
		log.Printf("Error: %v", error)
	} else {
		log.Printf("secevent was successfully created")
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{\"OK\"}"))
}

func main() {
	log.Print("Loading configuration")
	cfg := ctrl.GetConfigOrDie()
	client, error := amtdv1beta1client.NewClient(cfg)
	if error != nil {
		log.Panic(error)
	}
	secEventClient := client.SecurityEvents()
	falcoBackend := FalcoBackend{
		client: &secEventClient,
		ctx:    context.Background(),
	}
	port := getServerPort()

	log.Println("starting server, listening on port " + port)

	http.HandleFunc("/", falcoBackend.FalcoHandler)
	http.ListenAndServe(":"+port, nil)
}
