// Onion Courier client for sending files directly
// to ochome server, base64 encoded, without using
// the Mixnet

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

var startTime time.Time

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ocsend address:port < filename")
		os.Exit(1)
	}

	serverAddress := os.Args[1]
	if !strings.HasPrefix(serverAddress, "http://") && !strings.HasPrefix(serverAddress, "https://") {
		serverAddress = "http://" + serverAddress
	}
	serverURL := serverAddress + "/upload"

	fmt.Print("Connecting...\n")
	err := uploadFile(serverURL)
	if err != nil {
		fmt.Printf("Error uploading file: %v", err)
		os.Exit(1)
	}
}

func uploadFile(serverURL string) error {
	// Daten von stdin lesen
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %w", err)
	}

	if len(data) == 0 {
		return fmt.Errorf("no data received from stdin")
	}

	startTime = time.Now()

	encodedData := base64.StdEncoding.EncodeToString(data)
	
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("can't connect to the Tor proxy: %v", err)
	}
	
	httpTransport := &http.Transport{
		Dial: dialer.Dial,
	}
	client := &http.Client{
		Transport: httpTransport,
		Timeout:   30 * time.Second,
	}

	request, err := http.NewRequest("POST", serverURL, strings.NewReader(encodedData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	request.Header.Set("Content-Type", "text/plain")
	request.Header.Set("X-Content-Encoding", "base64")

	fmt.Print("Starting file transfer...\n")

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer response.Body.Close()

	// Server Response lesen
	responseBody, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s, body: %s", response.Status, string(responseBody))
	}

	elapsedTime := time.Since(startTime)
	fmt.Printf("\rFile transfer successful! Elapsed Time: %s\n", formatDuration(elapsedTime))

	return nil
}

func insertLineBreaks(data []byte, lineLength int) []byte {
	var result bytes.Buffer
	for i := 0; i < len(data); i += lineLength {
		end := i + lineLength
		if end > len(data) {
			end = len(data)
		}
		result.Write(data[i:end])
		if end < len(data) {
			result.WriteString("\n")
		}
	}
	return result.Bytes()
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
