package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

const (
	EMPTY_VALUE            = ""
	DEFAULT_WORKERS_AMOUNT = 10
)

var (
	shadowFilePath     string
	dictionaryFilePath string
	workersAmount      uint
)

var (
	mutex sync.Mutex
)

func init(){
	flag.StringVar(&shadowFilePath, "f", EMPTY_VALUE, "Path to the file containing the hashed passwords.")
	flag.StringVar(&shadowFilePath, "-file", EMPTY_VALUE, "see -f")

	flag.StringVar(&dictionaryFilePath, "d", EMPTY_VALUE, "Path to a dictionary file.")
	flag.StringVar(&dictionaryFilePath, "-dict", EMPTY_VALUE, "see -d")

	flag.UintVar(&workersAmount, "w", DEFAULT_WORKERS_AMOUNT, "Amount of workers to create the password.")
}

func isFileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err){
		return false
	}
	return !info.IsDir()
}

func argsCheck() {

	if shadowFilePath == EMPTY_VALUE || dictionaryFilePath == EMPTY_VALUE {
		fmt.Printf("Please use: %s -h\n",os.Args[0])
		os.Exit(1)
	}

	if !isFileExists(shadowFilePath){
		fmt.Println("Please enter a valid shadow file (-f)")
		os.Exit(1)
	}
	if !isFileExists(dictionaryFilePath){
		fmt.Println("Please enter a valid dictionary file (-d)")
		os.Exit(1)
	}
}

func main(){
	flag.Parse()

	argsCheck()

	words := make(chan string, 0)
	found := make(chan string, 0)

	var wg sync.WaitGroup

	shadowFile, err := os.Open(shadowFilePath)
	if err != nil {
		log.Fatalln(err)
	}
	defer shadowFile.Close()

	hashScanner := bufio.NewScanner(shadowFile)
	for hashScanner.Scan(){
		currentHash := hashScanner.Text()
		username, passwordHash := extractData(currentHash)

		for i := 0; i < int(workersAmount); i++ {
			wg.Add(1)
			go crackWorker(passwordHash, words, found, &wg)
		}

		dictFile, err := os.Open(dictionaryFilePath)
		if err != nil {
			log.Fatalln(err)
		}
		defer dictFile.Close()

		wordsScanner := bufio.NewScanner(dictFile)
		go func() {
			for wordsScanner.Scan(){
				password := wordsScanner.Text()
				words <- password
			}
			close(words)
		}()

		done := make(chan bool)
		go func() {
			wg.Wait()
			done <- true
		}()

		select {
		case f := <-found:
			fmt.Println(username)
			fmt.Println(f)
			return
		case <-done:
			fmt.Println("No password found")
			return
		}


	}



}

func extractData(hash string) (username, passwordHash string) {
	if strings.Contains(hash, ":"){
		username = strings.Split(hash, ":")[0]
		passwordHash = strings.Split(hash, ":")[1]
	}
	return
}

func crackWorker(passwordHash string, words <-chan string, found chan<- string, wg *sync.WaitGroup){
	defer wg.Done()
	saltSearch := strings.LastIndex(passwordHash, "$")
	salt := passwordHash[0:saltSearch + 1]

	for word := range words {
		mutex.Lock()
		cryptWord, err := crypt(word, salt)
		mutex.Unlock()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if cryptWord == passwordHash {
			found <- word
			return
		}
	}
}
