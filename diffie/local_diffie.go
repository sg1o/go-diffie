package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// generatePrimeNumber generates a prime number with a random bit size between minBits and maxBits.
func generatePrimeNumber(minBits, maxBits int) (*big.Int, error) {
	// Generate a random size between minBits and maxBits
	bitSize, err := rand.Int(rand.Reader, big.NewInt(int64(maxBits-minBits+1)))
	if err != nil {
		return nil, err
	}
	bitSize.Add(bitSize, big.NewInt(int64(minBits)))

	// Generate a prime number of the selected bit size
	prime, err := rand.Prime(rand.Reader, int(bitSize.Int64()))
	if err != nil {
		return nil, err
	}
	return prime, nil
}

// diffieHellman performs the Diffie-Hellman key exchange.
func diffieHellman(p *big.Int, g *big.Int) (*big.Int, *big.Int, error) {
	// Generate private key (a random number)
	private, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, nil, err
	}

	// Calculate public key: g^private mod p
	public := new(big.Int).Exp(g, private, p)

	return private, public, nil
}

func main() {
	// Generate a prime number for use in Diffie-Hellman with a size between 2048 and 2096 bits
	p, err := generatePrimeNumber(2048, 2096)
	if err != nil {
		panic(err)
	}
	fmt.Println("Generated Prime Number (p):", p)

	// Select a base g, usually a small number
	g := big.NewInt(2)
	fmt.Println("Base (g):", g)

	// User A generates their key pair
	privateA, publicA, err := diffieHellman(p, g)
	if err != nil {
		panic(err)
	}
	fmt.Println("User A Private Key:", privateA)
	fmt.Println("User A Public Key:", publicA)

	// User B generates their key pair
	privateB, publicB, err := diffieHellman(p, g)
	if err != nil {
		panic(err)
	}
	fmt.Println("User B Private Key:", privateB)
	fmt.Println("User B Public Key:", publicB)

	// Compute the shared key
	sharedKeyA := new(big.Int).Exp(publicB, privateA, p)
	sharedKeyB := new(big.Int).Exp(publicA, privateB, p)

	// Verify that both computed shared keys are equal
	fmt.Println("Shared Key computed by A:", sharedKeyA)
	fmt.Println("Shared Key computed by B:", sharedKeyB)
	fmt.Println("Do shared keys match:", sharedKeyA.Cmp(sharedKeyB) == 0)
}
