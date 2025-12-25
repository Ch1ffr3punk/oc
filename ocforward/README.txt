ocforward

A simple Go-based email forwarding system that forwards emails to .onion addresses via Tor. 
Designed to work with Postfix .forward files.

Features:

Automatic User Detection: Identifies the user account from which the email originates
Tor Integration: Uses Tor SOCKS5 proxy (port 9050) for .onion access
HTTP-based Forwarding: Sends raw emails via HTTP POST to port 8088
Retry Mechanism: Automatic retries with exponential backoff for transient failures
Simple Configuration: YAML-based per-user configuration

How It Works:

Postfix receives an email for a user
Postfix executes the user's .forward file which pipes to ocforward
ocforward reads the complete email from stdin
Looks up the user's .onion address in the config file
Forwards the raw email via Tor to http://[onion_address]:8088/upload
Returns success/failure to Postfix

Installation:

sudo cp ocforward /usr/local/bin/
sudo chmod 755 /usr/local/bin/ocforward

Configuration:

Create config directory and file:

sudo mkdir -p /etc/ocforward
sudo nano /etc/ocforward/ocforward.yaml
Example config:

yaml
users:
  alice:
    onion_address: "emailserver123.onion"
  
  bob:
    onion_address: "mailbox456.onion"
Set correct permissions:


sudo chmod 644 /etc/ocforward/ocforward.yaml

User Setup:

For each user that needs forwarding:

sudo -u username bash -c 'echo "|/usr/local/bin/ocforward" > ~/.forward'
sudo -u username chmod 644 ~/.forward
Configuration File
The config file (/etc/ocforward/ocforward.yaml) supports:

yaml
# Optional retry configuration (defaults shown)
max_retries: 3
initial_delay: 1      # seconds
max_delay: 30         # seconds
backoff_factor: 2.0
jitter: true

# User mappings
users:
  username1:
    onion_address: "onionaddr1.onion"
  
  username2:
    onion_address: "onionaddr2.onion"
