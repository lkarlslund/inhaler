package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/mmcloughlin/md4"
	"github.com/spf13/pflag"
)

func main() {
	hash := pflag.String("hash", "ntlm", "hash type to generate (ntlm)")
	parallel := pflag.Int("parallel", runtime.NumCPU(), "number of threads to use")
	pflag.Parse()

	queue := make(chan string, *parallel*4)
	var wg sync.WaitGroup

	for i := 0; i < *parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch *hash {
			case "ntlm":
				u16 := make([]byte, 16)
				mdfour := md4.New()
				for password := range queue {
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
					fmt.Println(password + ":" + hex.EncodeToString(md4))
				}
			}
		}()
	}

	// read lines from stdin and put them in the queue
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		queue <- strings.Trim(scanner.Text(), "\r\n")
	}
	close(queue)
	wg.Wait()
}
