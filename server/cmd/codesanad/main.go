package codesanad

import (
	"log"
	"net/http"
)

func main() {
	fs := http.FileServer(http.Dir("../../scripts"))

	http.Handle("/", fs)

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
