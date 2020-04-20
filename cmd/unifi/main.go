package main

import (
	"bytes"
	"encoding/hex"
	"github.com/jinzhu/configor"
	"github.com/sgrodzicki/unifi"
	"io/ioutil"
	"log"
	"net/http"
)

var Config = struct {
	ListenAddr string            `default:":8080" yaml:"listen"`
	InformUrl  string            `default:"http://unifi:8080/informUrl" yaml:"inform"`
	AuthKeys   map[string]string `required:"true" yaml:"auth_keys"`
}{}

func main() {
	if err := configor.New(&configor.Config{AutoReload: true}).Load(&Config, "config.yml"); err != nil {
		log.Fatalln(err)
	}

	log.Println("Server is ready to handle requests at", Config.ListenAddr)
	log.Println("Inform URL at", Config.InformUrl)

	http.HandleFunc("/inform", informHandler)

	log.Fatal(http.ListenAndServe(Config.ListenAddr, nil))
}

func informHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r)

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)

	pkt, err := unifi.ReadPacket(bytes.NewReader(body))
	if err != nil {
		log.Fatalf("cannot read packet: %v", err)
	}

	key := Config.AuthKeys[pkt.MAC.String()]

	if key == "" {
		log.Println("No key found for", pkt.MAC)
	} else {
		aesKey, err := hex.DecodeString(key)
		if err != nil || len(aesKey) != 16 {
			log.Fatalf("key must be 32 character long and hex-encoded: %v", err)
		}

		data, err := pkt.Data(aesKey)
		if err != nil {
			log.Printf("error decrypting packet: %v", err)
		}

		log.Println(string(data))
	}

	informResponse, _ := http.Post(Config.InformUrl, "application/x-binary", bytes.NewReader(body))

	log.Println(informResponse)
}
