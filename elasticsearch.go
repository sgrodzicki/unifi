package unifi

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"log"
	"sync"
	"time"
)

var (
	wg sync.WaitGroup
)

type Document struct {
	Time    time.Time `json:"@timestamp"`
	System  System    `json:"system"`
	ECS     ECS       `json:"ecs"`
	Event   Event     `json:"event"`
	Host    Host      `json:"host"`
	Agent   Agent     `json:"agent"`
	Service Service   `json:"service"`
}

type Event struct {
	Module  string `json:"module"`
	Dataset string `json:"dataset"`
}

type ECS struct {
	Version string `json:"version"`
}

type Network struct {
	Name string          `json:"name"`
	In   NetworkCounters `json:"in"`
	Out  NetworkCounters `json:"out"`
}

type NetworkCounters struct {
	Errors  int64 `json:"errors"`
	Dropped int64 `json:"dropped"`
	Packets int64 `json:"packets"`
	Bytes   int64 `json:"bytes"`
}

type Host struct {
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	Architecture string `json:"architecture"`
	OS           OS     `json:"os"`
	ID           string `json:"id"`
	IP           string `json:"ip"`
	MAC          string `json:"mac"`
	Uptime       int64  `json:"uptime"`
	Type         string `json:"type"`
}

type OS struct {
	Platform string `json:"platform"`
	Name     string `json:"name"`
	Family   string `json:"family"`
	Version  string `json:"version"`
	Kernel   string `json:"kernel"`
	Build    string `json:"build"`
}

type CPU struct {
	Steal   Percentage `json:"steal"`
	Total   Percentage `json:"total"`
	Cores   int64      `json:"cores"`
	System  Percentage `json:"system"`
	Nice    Percentage `json:"nice"`
	Irq     Percentage `json:"irq"`
	Idle    Percentage `json:"idle"`
	User    Percentage `json:"user"`
	IOWait  Percentage `json:"iowait"`
	Softirq Percentage `json:"softirq"`
}

type Percentage struct {
	Percentage float64 `json:"pct"`
}

type Load struct {
	Cores      int64     `json:"cores"`
	Normalized Intervals `json:"norm"`
	Intervals
}

type Intervals struct {
	OneMinute     float64 `json:"1"`
	FiveMinute    float64 `json:"5"`
	FifteenMinute float64 `json:"15"`
}

type System struct {
	CPU     *CPU     `json:"cpu,omitempty"`
	Load    *Load    `json:"load,omitempty"`
	Memory  *Memory  `json:"memory,omitempty"`
	Network *Network `json:"network,omitempty"`
}

type Memory struct {
	Actual MemoryActual `json:"actual"`
	Free   int64        `json:"free"`
	Swap   MemorySwap   `json:"swap"`
	Total  int64        `json:"total"`
	Used   MemoryUsed   `json:"used"`
}

type MemoryUsed struct {
	Bytes      int64   `json:"bytes"`
	Percentage float64 `json:"pct"`
}

type MemoryActual struct {
	Free int64      `json:"free"`
	Used MemoryUsed `json:"used"`
}

type MemorySwap struct {
	Free  int64      `json:"free"`
	Total int64      `json:"total"`
	Used  MemoryUsed `json:"used"`
}

type Agent struct {
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	Type     string `json:"type"`
}

type Service struct {
	Type string `json:"type"`
}

func Publish(es *elasticsearch.Client, docs []Document) {
	index := "metricbeat-7.6.2-2020.04.22-000001" // TODO: Create custom index and mappings

	for _, doc := range docs {
		wg.Add(1)
		go func(doc Document) {
			defer wg.Done()

			data, err := json.Marshal(doc)
			if err != nil {
				log.Println("Cannot marshal doc to JSON", doc, err)
				return
			}

			req := esapi.IndexRequest{
				Index:   index,
				Body:    bytes.NewReader(data),
				Refresh: "true",
			}

			res, err := req.Do(context.Background(), es)
			if err != nil {
				log.Println("Index request failed", err)
				return
			}

			defer res.Body.Close()

			if res.IsError() {
				log.Println(res.Status())
				return
			}
		}(doc)
	}
	wg.Wait()
}

func NewClient(host string, user string, pass string) (*elasticsearch.Client, error) {
	cfg := elasticsearch.Config{
		Addresses: []string{
			host,
		},
		Username: user,
		Password: pass,
	}

	es, err := elasticsearch.NewClient(cfg)

	if err != nil {
		return nil, err
	}

	return es, nil
}
