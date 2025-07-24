## Tor-Enabled data exchange with Client oc_client.go and Server oc_server.go

## Client oc_client.go
This client allows you to securely send files to a server
using the Tor network for enhanced privacy.   
It supports various options for flexibility and ease of use.

## Features

- Send data through Tor network
- Optional username support
- Use of a data file for server address:port and password
- Optional -h parameter to hide server response

## Requirements

- Go programming language
- `golang.org/x/net/proxy` package (for Tor support)

To install the required package, run:

go get golang.org/x/net/proxy

To compile oc_client.go and oc_server.go use:

$ go build -ldflags "-s -w" oc_client.go  
$ go build -ldflags "-s -w" oc_client.go


- [Tor Expert Bundle](https://www.torproject.org/download/tor/)


## Usage

### Basic Usage

Start tor.exe from the Tor Expert Bundle, then run the compiled oc_client.go program.

$ oc_client [-u username] [-d datafile] -f filename <server_address:port password>

### Using a Data File

$ oc_client [-u username] -d <data_file> -f filename

The data file should contain the server address:port and password, separated by a space, on a single line, ending with LF or CRLF.  
Multiple entries are supported.  
You can put comment lines, starting with #, in your data_file too.  
Please note:  The last entry in your data_file must be a single LF or CRLF and not more.

## Options

- `-u [username]`: Specify an optional username  
- `-f <filename>`: Specify the filename to be send, which is used on the server
- `-d <data_file>`: Use a data file containing server address:port and password
- `[-h`}: Hide server response

## Examples

1. Send data:

$ oc_client -f myfile.txt URL.onion:8080 mypassword


2. Send data with a username:

$ oc_client -u myusername URL.onion:8080 mypassword -f myfile.txt


3. Send data using a data file:

$ oc_client -d server_data.txt -f myfile.txt


## Security Considerations

- Be cautious when sending sensitive files and consider using encryption before sending.


## Server oc_server.go

## Requirements

- [Tor Browser Bundle](https://www.torproject.org/)

## Usage

On Windows open the torrc file located, for example, at:

C:\Tor Browser\Browser\TorBrowser\Data\Tor\

and add the following two lines:

HiddenServiceDir C:\Tor Browser\Browser\TorBrowser\Data\Tor\hidden_service  
HiddenServicePort 8080 127.0.0.1:8080

Restart Tor Browser and your Tor Hidden Service folder will be created at
the same location your torrc file resides. Look at the file 'hostname' which
contains the .onion URL for your Tor Hidden Service and give the address to
your friends.

Edit the password in line 13 in the source code and compile.

Now run the compiled oc_server.go with the -p parameter, for the file path files
should be stored.

Thats all.

You now have Tor and Tor Browser running to exchange files with your
friends, as long as Tor Browser with oc_server.go is running.

## Notes

You can omit the usage of Tor Browser and instead use only Tor-Expert-Bundle
and put the torrc file in the tor folder and start tor.exe with the -f parameter,
to use the torrc file.

If you put the torrc file into the tor folder, of Tor-Expert-Bundle, the torrc file may look like this:

HiddenServiceDir hidden_service  
HiddenServicePort 8080 127.0.0.1:8080  
HiddenServicePort 8081 127.0.0.1:8081  
HiddenServicePort 8082 127.0.0.1:8082  
HiddenServicePort 8083 127.0.0.1:8083  
HiddenServicePort 8084 127.0.0.1:8084  

## oc_node_server.go

oc_node_server.go uses [minicrypt](https://github.com/706f6c6c7578/minicrypt) to decrypt incoming data, prior it sends it to the next hop. The accepted message size for a node is limited to 4096 KB.
You can use the program, included in the genkeys folder, to generate a key pair.  

A node needs a special file format, containing an X-OC-To: header. Multiple hops are supported by chaining messages, like Cypherpunk Remailers (TypeI) do.
  
Why and when should you use nodes?  
In case you are not sure if your online computer is monitored by spyware.

You simply create your messages on an offline computer and encrypt your payload with minicrypt, prior sending data with your online computer.

## oc_email_server.go

oc_email_server.go uses your VPS MTA, which should have a whitelist defined, for reachable email domains.

It is advised that you always encrypt and sign your messages.

## oc_mail2node.go

oc_mail2node.go is a Gateway for sending webmail messages to Onion Courier nodes or directly to Onion Courier users.

## oc_m2n.go

An Onion Courier mail2news Gateway for dizum.com.

## Closing words

If you like the idea of point to point communication, without third-party
servers involved, consider a donation to the following Bitcoin address:

bc1qhgek8p5qcwz7r6502y8tvenkpsw9w5yafhatxk

or Monero address:

45TJx8ZHngM4GuNfYxRw7R7vRyFgfMVp862JqycMrPmyfTfJAYcQGEzT27wL1z5RG1b5XfRPJk97KeZr1svK8qES2z1uZrS

This project is dedicated to Alice and Bob.


