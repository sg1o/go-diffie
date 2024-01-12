package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
)

const minSize = 2048
const maxSize = 4096

// generatePrimeNumber generates a prime number of a specified bit size.
func generatePrimeNumber(minBits, maxBits int) (*big.Int, error) {
	bitSize, err := rand.Int(rand.Reader, big.NewInt(int64(maxBits-minBits+1)))
	if err != nil {
		return nil, err
	}
	bitSize.Add(bitSize, big.NewInt(int64(minBits)))

	prime, err := rand.Prime(rand.Reader, int(bitSize.Int64()))
	if err != nil {
		return nil, err
	}
	return prime, nil
}

// diffieHellman performs the Diffie-Hellman key exchange.
func diffieHellman(p *big.Int, g *big.Int) (*big.Int, *big.Int, error) {
	private, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, nil, err
	}

	public := new(big.Int).Exp(g, private, p)

	return private, public, nil
}

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		fmt.Println("Usage: interchange <port> [server IP]")
		os.Exit(1)
	}

	port := args[0]
	isServer := len(args) == 1

	if isServer {
		// Bob's code (Server)
		startServer(port)
	} else {
		// Alice's code (Client)
		connectToServer(args[1], port)
	}
}

func startServer(port string) {
	p, _ := generatePrimeNumber(minSize, maxSize)
	g := big.NewInt(2)

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println("Bob: Error listening:", err.Error())
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Println("Bob: Server is listening on port", port)

	conn, err := ln.Accept()
	if err != nil {
		fmt.Println("Bob: Error accepting:", err.Error())
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Fprintf(conn, p.String()+"\n")
	fmt.Fprintf(conn, g.String()+"\n")

	handleConnection(conn, p, g, "Bob")
}

func connectToServer(serverIP, port string) {
	conn, err := net.Dial("tcp", serverIP+":"+port)
	if err != nil {
		fmt.Println("Alice: Error connecting:", err.Error())
		os.Exit(1)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	pStr, _ := reader.ReadString('\n')
	gStr, _ := reader.ReadString('\n')

	p := new(big.Int)
	p.SetString(strings.TrimSpace(pStr), 10)
	g := new(big.Int)
	g.SetString(strings.TrimSpace(gStr), 10)

	handleConnection(conn, p, g, "Alice")
}

func handleConnection(conn net.Conn, p *big.Int, g *big.Int, name string) {
	private, public, _ := diffieHellman(p, g)
	fmt.Printf("%s: Private Key: %s\n", name, private)
	fmt.Printf("%s: Public Key: %s\n", name, public)

	if name == "Bob" {
		fmt.Println("Bob: Sending public key to Alice")
		_, err := fmt.Fprintf(conn, public.String()+"\n")
		if err != nil {
			fmt.Printf("Bob: Error sending public key: %s\n", err)
			return
		}
		receiveAndComputeSharedKey(conn, private, p, name)
	} else {
		receiveAndComputeSharedKey(conn, private, p, name)
		fmt.Println("Alice: Sending public key to Bob")
		_, err := fmt.Fprintf(conn, public.String()+"\n")
		if err != nil {
			fmt.Printf("Alice: Error sending public key: %s\n", err)
			return
		}
	}
}

func receiveAndComputeSharedKey(conn net.Conn, private *big.Int, p *big.Int, name string) *big.Int {
	fmt.Printf("%s: Waiting for the other party's public key\n", name)
	buffer, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("%s: Error reading public key: %s\n", name, err)
		os.Exit(1)
	}

	otherPublic := new(big.Int)
	_, ok := otherPublic.SetString(strings.TrimSpace(buffer), 10)
	if !ok {
		fmt.Printf("%s: Error parsing public key\n", name)
		os.Exit(1)
	}
	fmt.Printf("%s: Received and parsed public key: %s\n", name, otherPublic)

	sharedKey := new(big.Int).Exp(otherPublic, private, p)
	fmt.Printf("%s: Computed Shared Key: %s\n", name, sharedKey)
	return sharedKey
}
