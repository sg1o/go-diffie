# secomm

## Description
`secomm` is a command-line tool written in Go for secure communication. It
allows users to securely send and receive files or directories over a network.
The tool uses Diffie-Hellman for key exchange, AES for encryption, and ZIP
compression for efficient file transmission.

## Requirements
- Go (Version 1.x or later)

## Installation
Clone the repository and build the program:

```bash
git clone https://github.com/your-username/secomm.git
cd secomm
go build .
sudo mv secomm /usr/bin/
```

And ready to play

## Usage
### Sending Files
To send a file or directory, run:

```bash
./secomm -s <path> <port>
```

Where `<path>` is the path to the file or directory you want to send, and
`<port>` is the port number on which the server will listen.

### Receiving Files
To receive a file, run:

```bash
./secomm -r <port> <ip>
```

Where `<port>` is the port number to connect to, and `<ip>` is the IP address
of the server.

### Flags
- `-v`: Verbose output.
- `-vv`: Very verbose output.
- `--help`: Display help information.

## Examples
Start a server to send a file:

```bash
./secomm -s ./example.txt 8080
```

Connect to a server to receive a file:

```bash
./secomm -r 8080 192.168.1.100
```

## Contributing
Contributions to `secomm` are welcome! Please follow these steps to contribute:
1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch-name`.
3. Make your changes and commit them: `git commit -m 'commit message'`.
4. Push to the original branch: `git push origin secomm/feature-branch-name`.
5. Create the pull request.

Alternatively, see the GitHub documentation on [creating a pull request](https://help.github.com/articles/creating-a-pull-request/).
