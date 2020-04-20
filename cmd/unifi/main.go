package main

import (
	"bytes"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
)

var (
	listenAddr = flag.String("listen", ":8080", "listen address")
	informUrl  = flag.String("inform", "http://unifi:8080/informUrl", "inform url")
)

func main() {
	flag.Parse()

	log.Println("Server is ready to handle requests at", *listenAddr)
	log.Println("Inform URL at", *informUrl)

	http.HandleFunc("/inform", informHandler)

	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}

func informHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r)

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)

	informResponse, _ := http.Post(*informUrl, "application/x-binary", bytes.NewReader(body))

	log.Println(informResponse)
}
