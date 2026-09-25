// KeyNest CLI deliberately fetches values only for an authorized child process.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type config struct{ Server, Token string }
type valuesResponse struct { Values map[string]string `json:"values"` }

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil { return "", err }
	return filepath.Join(dir, "keynest", "config.json"), nil
}
func loadConfig() (config, error) {
	path, err := configPath(); if err != nil { return config{}, err }
	b, err := os.ReadFile(path); if err != nil { return config{}, err }
	var c config
	return c, json.Unmarshal(b, &c)
}
func saveConfig(c config) error {
	path, err := configPath(); if err != nil { return err }
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil { return err }
	b, err := json.Marshal(c); if err != nil { return err }
	return os.WriteFile(path, b, 0600)
}
func usage() { fmt.Fprintln(os.Stderr, "Usage: keynest login --server URL --token knst_... | keynest run --environment UUID -- command [args...]") }
func main() {
	if len(os.Args) < 2 { usage(); os.Exit(2) }
	var err error
	switch os.Args[1] { case "login": err = login(os.Args[2:]); case "logout": err = logout(); case "run": err = run(os.Args[2:]); default: usage(); err = errors.New("unsupported command") }
	if err != nil { fmt.Fprintln(os.Stderr, "keynest:", err); os.Exit(1) }
}
func login(args []string) error {
	var server, token string
	for len(args) > 0 {
		switch args[0] {
		case "--server": if len(args) < 2 { return errors.New("missing --server value") }; server, args = args[1], args[2:]
		case "--token": if len(args) < 2 { return errors.New("missing --token value") }; token, args = args[1], args[2:]
		default: return fmt.Errorf("unknown login flag %q", args[0])
		}
	}
	if !strings.HasPrefix(server, "https://") || !strings.HasPrefix(token, "knst_") { return errors.New("login requires an HTTPS server and a KeyNest service token") }
	// Do not accept passwords in the CLI. Device authorization will replace token paste in a later compatible flow.
	return saveConfig(config{Server: strings.TrimRight(server, "/"), Token: token})
}
func logout() error { path, err := configPath(); if err != nil { return err }; return os.Remove(path) }
func run(args []string) error {
	var environment string
	for len(args) > 0 && args[0] != "--" { if args[0] != "--environment" || len(args) < 2 { return errors.New("run requires --environment UUID followed by -- command") }; environment, args = args[1], args[2:] }
	if len(args) < 2 || args[0] != "--" { return errors.New("missing child command after --") }
	c, err := loadConfig(); if err != nil { return errors.New("not logged in") }
	values, err := fetchValues(c, environment); if err != nil { return err }; defer clear(values)
	child := exec.Command(args[1], args[2:]...); child.Env = mergedEnvironment(values); child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err = child.Start(); err != nil { return err }
	stopForwarding := forwardSignals(child.Process); err = child.Wait(); stopForwarding()
	if exit, ok := err.(*exec.ExitError); ok { os.Exit(exit.ExitCode()) }
	return err
}
func fetchValues(c config, environment string) (map[string]string, error) {
	request, err := http.NewRequest(http.MethodGet, c.Server+"/api/v1/cli/environments/"+environment+"/values", nil); if err != nil { return nil, err }
	request.Header.Set("Authorization", "Bearer "+c.Token)
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(request); if err != nil { return nil, err }; defer response.Body.Close()
	if response.StatusCode != http.StatusOK { _, _ = io.Copy(io.Discard, response.Body); return nil, fmt.Errorf("secret fetch failed: %s", response.Status) }
	var payload valuesResponse
	if err = json.NewDecoder(response.Body).Decode(&payload); err != nil { return nil, err }
	for key, value := range payload.Values { if strings.ContainsRune(key, '=') || strings.ContainsRune(key, 0) || strings.ContainsRune(value, 0) { return nil, errors.New("server returned invalid environment entry") } }
	return payload.Values, nil
}
func mergedEnvironment(values map[string]string) []string { result := os.Environ(); for key, value := range values { result = append(result, key+"="+value) }; return result }
func clear(values map[string]string) { for key := range values { values[key] = ""; delete(values, key) } }
