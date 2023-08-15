package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/runner"
)

func main() {
	binaryRes, _ := RunHttpxAsBinary("projectdiscovery.io", false, "-sc -cl -title -td -hash sha256 -wc -lc -nc")
	moduleRes, _ := RunHttpxAsModule([]string{"projectdiscovery.io"}, 1)
	fmt.Printf("BINARY RESULTS:\n%#v\n\n", binaryRes)
	fmt.Printf("MODULE RESULTS:\n%#v\n", moduleRes)

}

func RunHttpxAsBinary(url string, debug bool, extra ...string) ([]string, error) {
	cmd := exec.Command("bash", "-c")
	cmdLine := `echo "` + url + `" | httpx `
	cmdLine += strings.Join(extra, " ")
	if debug {
		cmdLine += " -debug"
		cmd.Stderr = os.Stderr
	} else {
		cmdLine += " -silent"
	}

	cmd.Args = append(cmd.Args, cmdLine)

	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	parts := []string{}
	items := strings.Split(string(data), "\n")
	for _, i := range items {
		if i != "" {
			parts = append(parts, i)
		}
	}
	return parts, nil
}

func RunHttpxAsModule(domains []string, threads int) ([]string, error) {
	// increase the verbosity (optional)
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	// results of each http req
	results := []string{}

	var mu sync.Mutex
	options := runner.Options{
		RandomAgent:     true,
		OutputCDN:       true,
		Threads:         threads,
		Methods:         "GET",
		InputTargetHost: domains,
		ExcludeCDN:      false,
		OnResult: func(r runner.Result) {
			// handle error
			if r.Err != nil {
				log.Printf("[Err] %s: %s\n", r.Input, r.Err)
				return
			}
			mu.Lock()
			results = append(results, fmt.Sprintf("%v %v %v %v %v %v %v %v", r.URL, r.StatusCode, r.ContentLength, r.Title, r.Technologies, r.Hashes, r.Words, r.Lines))
			mu.Unlock()
		},
	}

	if err := options.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("option validation failed: %v", err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("creating httpx runner failed: %v", err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	return results, nil
}
