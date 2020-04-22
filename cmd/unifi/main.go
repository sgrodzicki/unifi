package main

import (
	"bytes"
	"github.com/jinzhu/configor"
	"github.com/sgrodzicki/unifi"
	"io/ioutil"
	"log"
	"net/http"
)

var Config = struct {
	ListenAddr    string            `default:":8080" yaml:"listen"`
	InformUrl     string            `default:"http://unifi:8080/informUrl" yaml:"inform"`
	AuthKeys      map[string]string `yaml:"auth_keys"`
	Elasticsearch Elasticsearch
}{}

type Elasticsearch struct {
	Host     string `default:"localhost:9200"`
	Username string `default:"elastic"`
	Password string `default:"changeme"`
}

func main() {
	if err := configor.New(&configor.Config{AutoReload: true}).Load(&Config, "config.yml"); err != nil {
		log.Fatal(err)
	}

	log.Println("Server is ready to handle requests at", Config.ListenAddr)
	log.Println("Inform URL at", Config.InformUrl)

	http.HandleFunc("/inform", informHandler)

	log.Fatal(http.ListenAndServe(Config.ListenAddr, nil))
}

func informHandler(proxyResponse http.ResponseWriter, clientRequest *http.Request) {
	if clientRequest.Method != http.MethodPost {
		proxyResponse.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	clientPayload, err := ioutil.ReadAll(clientRequest.Body)
	if err != nil {
		log.Println("Malformed client payload", err)
		proxyResponse.WriteHeader(http.StatusInternalServerError)
		return
	}

	serverResponse, err := forwardRequest(Config.InformUrl, clientPayload)
	if err != nil {
		log.Println("Invalid response from upstream server", Config.InformUrl, err)
		proxyResponse.WriteHeader(http.StatusBadGateway)
		return
	}

	defer serverResponse.Body.Close()

	serverPayload, err := ioutil.ReadAll(serverResponse.Body)
	if err != nil {
		log.Println("Malformed server payload", err)
		proxyResponse.WriteHeader(http.StatusInternalServerError)
		return
	}

	proxyResponse.Header().Set("Content-Type", "application/x-binary")
	proxyResponse.WriteHeader(serverResponse.StatusCode)
	_, _ = proxyResponse.Write(serverPayload)

	// Access log
	log.Println(clientRequest.RemoteAddr, clientRequest.ContentLength, serverResponse.StatusCode, serverResponse.ContentLength)

	collectMetrics(clientPayload)
}

func forwardRequest(url string, body []byte) (*http.Response, error) {
	response, err := http.Post(url, "application/x-binary", bytes.NewReader(body))

	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		log.Println(response)
	}

	return response, nil
}

func collectMetrics(encodedPayload []byte) {
	packet, err := unifi.ParsePayload(bytes.NewReader(encodedPayload))
	if err != nil {
		log.Println("Cannot parse payload", err)
		return
	}

	key := Config.AuthKeys[packet.MAC.String()]
	if key == "" {
		log.Println("No authentication key found for", packet.MAC)
		return
	}

	payload, err := unifi.Decode(key, packet)
	if err != nil {
		log.Println("Cannot decode packet", err)
		return
	}

	if payload.InformAsNotif {
		// No metrics to collect
		return
	}

	docs := unifi.GenerateNetworkDocs(payload)
	docs = append(docs, unifi.GenerateCpuDoc(payload), unifi.GenerateLoadDoc(payload), unifi.GenerateMemoryDoc(payload))

	es, _ := unifi.NewClient(Config.Elasticsearch.Host, Config.Elasticsearch.Username, Config.Elasticsearch.Password)
	unifi.Publish(es, docs)
}
