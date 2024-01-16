package main

import (
	"archive/zip"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	minSize = 2048
	maxSize = 4096
)

var verbosityLevel int

// displayHelp prints the usage instructions.
func displayHelp() {
	fmt.Println("secomm: Secure Communication Tool")
	fmt.Println("Usage:")
	fmt.Println("  secomm -s <path> <port>   Start server and send file/folder.")
	fmt.Println("  secomm -r <port> <ip>     Connect to server and receive file.")
	fmt.Println("Flags:")
	fmt.Println("  -v                       Verbose output.")
	fmt.Println("  -vv                      Very verbose output.")
	fmt.Println("  --help                   Display this help message.")
}

func main() {
	// Manual parsing of -v and --help Flags
	args := os.Args
	for _, arg := range args {
		if arg == "-v" {
			verbosityLevel = 1
		} else if arg == "-vv" {
			verbosityLevel = 2
		} else if arg == "--help" {
			displayHelp()
			return
		}
	}

	// Checking the minimum number of arguments
	if len(args) < 3 {
		fmt.Println("Usage: secomm -s <path> <port> or secomm -r <port> <ip>")
		os.Exit(1)
	}

	// Handling -s and -r subcommands
	switch args[1] {
	case "-s":
		if len(os.Args) < 4 {
			fmt.Println("Error: Incorrect format for -s. Usage: secomm -s <path> <port>")
			os.Exit(1)
		}

		path, port := os.Args[2], os.Args[3]
		if !isValidPath(path) {
			fmt.Println("Error: The provided path does not exist.")
			os.Exit(1)
		}
		if !isValidPort(port) {
			fmt.Println("Error: The provided port is not valid.")
			os.Exit(1)
		}

		key, conn := startServer(port)
		if verbosityLevel >= 1 {
			fmt.Printf("Computed private Key: %s\n", key)
		}

		fmt.Println("Compressing data")
		zipPath, _ := compress(path)
		if verbosityLevel >= 1 {
			fmt.Println("Zip Path: ", zipPath)
		}
		encPath, _ := cipherFile(zipPath, key)
		if verbosityLevel >= 1 {
			fmt.Println("Enc Path: ", encPath)
		}
		fmt.Println("Start sending file")
		received := sendFile(conn, encPath)
		if received != nil {
			fmt.Println("[!]File sent successfully")
		}
		deleteS(zipPath)

	case "-r":
		if len(os.Args) < 4 {
			fmt.Println("Error: Incorrect format for -r. Usage: secomm -r <ip> <port>")
			os.Exit(1)
		}

		port, ip := os.Args[3], os.Args[2]
		if !isValidPort(port) {
			fmt.Println("Error: The provided port is not valid.")
			os.Exit(1)
		}
		if !isValidIP(ip) {
			fmt.Println("Error: The provided IP address format is not valid.")
			os.Exit(1)
		}

		key, conn := connectToServer(ip, port)
		if verbosityLevel >= 1 {
			fmt.Printf("Computed private Key: %s\n", key)
		}
		encFileReceived, err := receiveFile(conn)
		if err != nil {
			fmt.Println("Failed to receive file:", err)
			os.Exit(1)
		}
		fmt.Println("Received filepath: ", encFileReceived)
		fmt.Println("Decrypt file")
		zipPath, err := decryptFile(encFileReceived, key)
		if err != nil {
			fmt.Println("Failed to decrypt file:", err)
			os.Exit(1)
		}
		if verbosityLevel >= 1 {
			fmt.Println("Uncompress file: ", zipPath)
		}
		filePath, err := uncompress(zipPath)
		if err != nil {
			fmt.Println("Failed to uncompress file:", err)
			os.Exit(1)
		}
		fmt.Println("File received in ", filePath)
		deleteR()

	default:
		fmt.Println("Error: Invalid argument. Usage: secomm -s <path> <port> or secomm -r <ip> <port>")
		os.Exit(1)
	}

	switch args[1] {
	case "-r":
		deleteR()
	}

}

// Helper function to check if a path is valid (file or folder exists)
func isValidPath(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// Helper function to check if a port number is valid
func isValidPort(port string) bool {
	p, err := strconv.Atoi(port)
	return err == nil && p > 0 && p <= 65535
}

// Helper function to check if an IP address is valid
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

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

func startServer(port string) (*big.Int, net.Conn) {
	p, _ := generatePrimeNumber(minSize, maxSize)
	g := big.NewInt(2)

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println("Server: Error listening:", err.Error())
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Println("Server: Server is listening on port", port)

	conn, err := ln.Accept()
	if err != nil {
		fmt.Println("Server: Error accepting:", err.Error())
		os.Exit(1)
	}

	fmt.Fprintf(conn, p.String()+"\n")
	fmt.Fprintf(conn, g.String()+"\n")

	return handleConnection(conn, p, g, "Server"), conn
}

func connectToServer(serverIP, port string) (*big.Int, net.Conn) {

	conn, err := net.Dial("tcp", serverIP+":"+port)
	if err != nil {
		fmt.Println("Client: Error connecting:", err.Error())
		os.Exit(1)
	}

	reader := bufio.NewReader(conn)
	pStr, _ := reader.ReadString('\n')
	gStr, _ := reader.ReadString('\n')

	p := new(big.Int)
	p.SetString(strings.TrimSpace(pStr), 10)
	g := new(big.Int)
	g.SetString(strings.TrimSpace(gStr), 10)

	return handleConnection(conn, p, g, "Client"), conn

}

func handleConnection(conn net.Conn, p *big.Int, g *big.Int, name string) *big.Int {

	private, public, _ := diffieHellman(p, g)
	if verbosityLevel >= 2 {
		fmt.Printf("%s: Private Key: %s\n", name, private)
		fmt.Printf("%s: Public Key: %s\n", name, public)
	}

	if name == "Server" {

		fmt.Println("Server: Sending public key to the client")
		_, err := fmt.Fprintf(conn, public.String()+"\n")
		if err != nil {
			fmt.Printf("Server: Error sending public key: %s\n", err)
			os.Exit(1)
		}
		return receiveAndComputeSharedKey(conn, private, p, name)

	} else {

		key := receiveAndComputeSharedKey(conn, private, p, name)
		fmt.Println("Client: Sending public key to the server")
		_, err := fmt.Fprintf(conn, public.String()+"\n")
		if err != nil {
			fmt.Printf("Client: Error sending public key: %s\n", err)
			os.Exit(1)
		}

		return key

	}

}

func receiveAndComputeSharedKey(conn net.Conn, private *big.Int, p *big.Int, name string) *big.Int {

	if verbosityLevel >= 1 {
		fmt.Printf("%s: Waiting for the other party's public key\n", name)
	}
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
	if verbosityLevel >= 2 {
		fmt.Printf("%s: Received and parsed public key: %s\n", name, otherPublic)
	}

	sharedKey := new(big.Int).Exp(otherPublic, private, p)
	if verbosityLevel >= 1 {
		fmt.Printf("%s: Computed Shared Key: %s\n", name, sharedKey)
	}
	return sharedKey

}

func compress(source string) (string, error) {
	zipPath := source + ".zip"
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	info, err := os.Stat(source)
	if err != nil {
		return "", err
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}

	if baseDir != "" {
		// Compressing a directory
		err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if path == source {
				return nil
			}

			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			header.Name = filepath.ToSlash(filepath.Join(baseDir, path[len(source)+1:]))
			if info.IsDir() {
				header.Name += "/"
			} else {
				header.Method = zip.Deflate
			}

			writer, err := archive.CreateHeader(header)
			if err != nil {
				return err
			}

			if !info.IsDir() {
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				defer file.Close()
				_, err = io.Copy(writer, file)
			}
			return err
		})
	} else {
		// Compressing a single file
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return "", err
		}
		header.Name = filepath.Base(source)
		header.Method = zip.Deflate

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return "", err
		}

		file, err := os.Open(source)
		if err != nil {
			return "", err
		}
		defer file.Close()
		_, err = io.Copy(writer, file)
		if err != nil {
			return "", err
		}
	}

	if err != nil {
		return "", err
	}

	return zipPath, nil
}

// cipher encrypts a file with AES using a password derived from a big.Int
func cipherFile(filePath string, password *big.Int) (string, error) {
	// Convert big.Int to AES key
	key := bigIntToAESKey(password)

	// Read file content
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the content
	encrypted := gcm.Seal(nonce, nonce, content, nil)

	// Save encrypted content to a new file
	encryptedFilePath := filePath + ".enc"
	err = ioutil.WriteFile(encryptedFilePath, encrypted, 0644)
	if err != nil {
		return "", err
	}

	// Return the path of the encrypted file
	return encryptedFilePath, nil
}

// bigIntToAESKey convierte un big.Int en una clave AES de 32 bytes
func bigIntToAESKey(number *big.Int) []byte {
	key := number.Bytes()
	// Asegurar que la clave tenga exactamente 32 bytes
	if len(key) < 32 {
		extendedKey := make([]byte, 32)
		copy(extendedKey[32-len(key):], key)
		key = extendedKey
	} else if len(key) > 32 {
		key = key[:32]
	}
	return key
}

// decryptFile decrypts an AES-encrypted file using a password derived from a big.Int
func decryptFile(encryptedFilePath string, password *big.Int) (string, error) {
	// Convert big.Int to AES key
	key := bigIntToAESKey(password)

	// Read encrypted file content
	encryptedContent, err := ioutil.ReadFile(encryptedFilePath)
	if err != nil {
		return "", err
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract the nonce
	nonceSize := gcm.NonceSize()
	if len(encryptedContent) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := encryptedContent[:nonceSize], encryptedContent[nonceSize:]

	// Decrypt the content
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	// Save decrypted content to a new file
	decryptedFilePath := encryptedFilePath + ".zip"
	err = ioutil.WriteFile(decryptedFilePath, decrypted, 0644)
	if err != nil {
		return "", err
	}

	// Return the path of the decrypted file
	return decryptedFilePath, nil
}

func uncompress(zipPath string) (string, error) {
	if verbosityLevel >= 1 {
		fmt.Println("Starting to uncompress:", zipPath)
	}

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		fmt.Println("Error opening zip file:", err)
		return "", err
	}
	defer reader.Close()

	extractDir := "received_data"
	fmt.Println("Extracting to directory:", extractDir)
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		fmt.Println("Error creating extraction directory:", err)
		return "", err
	}

	for _, file := range reader.File {
		fullPath := filepath.Join(extractDir, file.Name)
		if verbosityLevel >= 1 {
			fmt.Println("Processing:", fullPath, "IsDir:", file.FileInfo().IsDir())
		}

		if file.FileInfo().IsDir() {
			fmt.Println("Creating directory:", fullPath)
			if err := os.MkdirAll(fullPath, file.Mode()); err != nil {
				fmt.Println("Error creating directory:", err)
				return "", err
			}
			continue
		}

		// Ensure the file's directory exists
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			fmt.Println("Error creating parent directory for file:", err)
			return "", err
		}

		outFile, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			fmt.Println("Error creating file:", err)
			return "", err
		}

		fileInZip, err := file.Open()
		if err != nil {
			fmt.Println("Error opening file in zip:", err)
			outFile.Close()
			return "", err
		}
		if verbosityLevel >= 1 {
			fmt.Println("Writing file:", fullPath)
		}
		if _, err := io.Copy(outFile, fileInZip); err != nil {
			fmt.Println("Error writing file:", err)
			outFile.Close()
			fileInZip.Close()
			return "", err
		}

		outFile.Close()
		fileInZip.Close()
	}

	fmt.Println("Uncompression completed successfully")
	return extractDir, nil
}

type FileData struct {
	Checksum string `json:"checksum"`
	Data     string `json:"data"`
}

func sendFile(conn net.Conn, filePath string) error {
	if verbosityLevel >= 1 {
		fmt.Println("Starting to send file:", filePath)
	}

	// Read and encode the file
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return err
	}
	encodedData := base64.StdEncoding.EncodeToString(fileData)
	fmt.Println("File data encoded")

	// Calculate checksum
	checksum := fmt.Sprintf("%x", sha256.Sum256(fileData))
	if verbosityLevel >= 1 {
		fmt.Println("Checksum calculated:", checksum)
	}

	// Create JSON object
	fileDataObject := FileData{
		Checksum: checksum,
		Data:     encodedData,
	}
	jsonData, err := json.Marshal(fileDataObject)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return err
	}

	// Send JSON data
	_, err = conn.Write(jsonData)
	if err != nil {
		fmt.Println("Error sending data:", err)
		return err
	}

	fmt.Println("File sent successfully")
	return nil
}

func receiveFile(conn net.Conn) (string, error) {
	fmt.Println("Starting to receive file")

	// Read JSON data from connection
	jsonData, err := ioutil.ReadAll(conn)
	if err != nil {
		fmt.Println("Error reading from connection:", err)
		os.Exit(1)
	}
	if verbosityLevel >= 1 {
		fmt.Println("JSON data received")
	}

	// Unmarshal JSON data
	var fileData FileData
	if err := json.Unmarshal(jsonData, &fileData); err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		os.Exit(1)
	}

	// Decode file data from base64
	decodedData, err := base64.StdEncoding.DecodeString(fileData.Data)
	if err != nil {
		fmt.Println("Error decoding base64 data:", err)
		os.Exit(1)
	}
	fmt.Println("File data decoded")

	// Calculate checksum
	checksum := fmt.Sprintf("%x", sha256.Sum256(decodedData))
	if checksum != fileData.Checksum {
		fmt.Println("Checksum mismatch: expected", fileData.Checksum, "got", checksum)
		os.Exit(1)

	}
	fmt.Println("Checksum verified successfully")

	// Write file data to a file
	const fileName = "received.file.enc"
	err = ioutil.WriteFile(fileName, decodedData, 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		os.Exit(1)
	}
	if verbosityLevel >= 1 {
		fmt.Println("File received and written to:", fileName)
	}
	return fileName, nil
}

func deleteR() {
	go fmt.Println("Cleaning files...")

	os.Remove("./received.file.enc")
	os.Remove("./received.file.enc.zip")
}

func deleteS(fileName string) {
	go fmt.Println("Cleaning files...")

	os.Remove(fileName)
	os.Remove(fileName + ".enc")
}
