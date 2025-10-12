// Onion Courier client for sending files directly to ochome server

package main

import (
	"bytes"
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
	startTime = time.Now()

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %w", err)
	}

	if len(data) == 0 {
		return fmt.Errorf("no data received from stdin")
	}

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

	request, err := http.NewRequest("POST", serverURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	request.Header.Set("Content-Type", "application/octet-stream")

	fmt.Print("Starting file transfer...\n")

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer response.Body.Close()

	responseBody, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s, body: %s", response.Status, string(responseBody))
	}

	elapsedTime := time.Since(startTime)
	fmt.Printf("\rFile transfer successful! Elapsed Time: %s\n", formatDuration(elapsedTime))

	return nil
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
