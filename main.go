package main

import (
	"bufio"
	"encoding/hex"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/mmcloughlin/md4"
	"github.com/spf13/pflag"
)

type hashed struct {
	password string
	hash     string
}

func main() {
	hash := pflag.String("hash", "ntlm", "hash type to generate (ntlm)")
	parallel := pflag.Int("parallel", runtime.NumCPU(), "number of threads to use")
	inputname := pflag.String("input", "", "file to read passwords from, blank for stdin")
	outputname := pflag.String("output", "", "file to write hashed passwords to, blank for stdout")
	pflag.Parse()

	plaintextqueue := make(chan string, *parallel*4)
	hashedqueue := make(chan hashed, *parallel*4)

	var producerWait, consumerWait sync.WaitGroup

	for i := 0; i < *parallel; i++ {
		producerWait.Add(1)
		go func() {
			defer producerWait.Done()
			switch *hash {
			case "ntlm":
				u16 := make([]byte, 16)
				mdfour := md4.New()
				for password := range plaintextqueue {
					/* Add all bytes, as well as the 0x00 of UTF-16 */
					utf16encoded := utf16.Encode([]rune(password))
					if cap(u16) < len(utf16encoded)*2 {
						u16 = make([]byte, len(utf16encoded)*2)
					}
					u16 = u16[:len(utf16encoded)*2]
					for i, b := range utf16encoded {
						u16[i*2] = byte(b)
						u16[i*2+1] = byte(b >> 8)
					}

					/* Hash the byte array with MD4 */
					mdfour.Reset()
					mdfour.Write(u16)
					md4 := mdfour.Sum(nil)

					/* Return the output */
					hashedqueue <- hashed{
						password: password,
						hash:     hex.EncodeToString(md4),
					}
				}
			}
		}()
	}

	var writeto io.WriteCloser
	writeto = os.Stdout
	if *outputname != "" {
		outputfile, err := os.Create(*outputname)
		if err != nil {
			panic("could not write to" + *outputname + ": " + err.Error())
		}
		writeto = outputfile
	}
	defer writeto.Close()

	output := bufio.NewWriter(writeto)
	defer output.Flush()

	consumerWait.Add(1)
	go func() {
		defer consumerWait.Done()
		var sb strings.Builder
		for hashed := range hashedqueue {
			sb.Reset()
			sb.Grow(len(hashed.password) + len(hashed.hash) + 2)
			sb.WriteString(hashed.password)
			sb.WriteString(":")
			sb.WriteString(hashed.hash)
			sb.WriteString("\n")
			_, err := output.WriteString(sb.String())
			if err != nil {
				panic("could not write: " + err.Error())
			}
		}
	}()

	// read lines from stdin and put them in the queue
	var readfrom io.ReadCloser
	readfrom = os.Stdin

	if *inputname != "" {
		inputfile, err := os.Open(*inputname)
		if err != nil {
			panic("could not read from" + *inputname + ": " + err.Error())
		}
		readfrom = inputfile
	}
	defer readfrom.Close()

	scanner := bufio.NewScanner(bufio.NewReaderSize(readfrom, 1024*1024))
	for scanner.Scan() {
		line := scanner.Bytes()
		// for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == '\n') {
		// 	line = line[:len(line)-1]
		// }
		plaintextqueue <- string(line)
	}
	close(plaintextqueue)
	producerWait.Wait()

	close(hashedqueue)
	consumerWait.Wait()
}
