package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	TRUFFLEHOG_PATH    string
	TRUFFLEHOG_PROJECT string
)

type TruffleHogFilesystem struct {
	File string `json:"file"`
}

type TruffleHogData struct {
	FS TruffleHogFilesystem `json:"Filesystem"`
}

type SourceMetadata struct {
	Data TruffleHogData `json:"Data"`
}

type TruffleHogResult struct {
	Metadata     SourceMetadata `json:"SourceMetadata"`
	SourceID     int            `json:"SourceID"`
	SourceType   int            `json:"SourceType"`
	SourceName   string         `json:"SourceName"`
	DetectorType int            `json:"DetectorType"`
	DetectorName string         `json:"DetectorName"`
	Verified     bool           `json:"Verified"`
	Raw          string         `json:"Raw"`
	Redacted     string         `json:"Redacted"`
}

func RunTruffleHog(path string) error {
	log.Printf("[TruffleHog] Scanning: %s", path)

	cmd := exec.Command(TRUFFLEHOG_PATH, "filesystem", "--directory", path, "--json")

	r, _ := cmd.StdoutPipe()
	scanner := bufio.NewScanner(r)

	wg := sync.WaitGroup{}
	wg.Add(1)

	rows := []table.Row{}
	header := table.Row{"DETECTOR NAME", "FILE", "RAW"}

	go func() {
		defer wg.Done()

		for scanner.Scan() {
			line := scanner.Bytes()

			result := TruffleHogResult{}

			err := json.Unmarshal(line, &result)
			if err != nil {
				log.Errorf("error in JSON unmarshal - err: %v", err)
				continue
			}

			raw := result.Raw
			if len(raw) >= 15 {
				raw = fmt.Sprintf("%s...", result.Raw[:15])
			}

			rows = append(rows, table.Row{
				result.DetectorName,
				result.Metadata.Data.FS.File,
				raw,
			})
		}
	}()

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("error running TruffleHog - err: %v", err)
	}

	wg.Wait()

	if len(rows) > 0 {
		CreateTable(header, rows)
	}

	return nil
}

var trufflehogCmd = &cobra.Command{
	Use:   "trufflehog",
	Short: "Find leaked credentials with TruffleHog",
	Long:  `Find leaked credentials with TruffleHog`,
	Run: func(cmd *cobra.Command, args []string) {
		projects, err := ioutil.ReadDir(TRUFFLEHOG_PROJECT)
		if err != nil {
			log.Fatal(err)
		}

		for _, proj := range projects {
			if proj.IsDir() {
				path := fmt.Sprintf("%s/%s", TRUFFLEHOG_PROJECT, proj.Name())

				full_path, err := filepath.Abs(path)
				if err != nil {
					log.Fatalf("error getting absolute path - err: %v", err)
				}

				err = RunTruffleHog(full_path)
				if err != nil {
					log.Error(err)
				}
				fmt.Println()
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(trufflehogCmd)

	trufflehogCmd.Flags().StringVarP(&TRUFFLEHOG_PROJECT, "projects", "p", "./gitlab/projects", "Path to Downloaded Projects")

	var err error

	if TRUFFLEHOG_PATH, err = GetConfigParam("trufflehog.path"); err != nil {
		log.Fatal(err)
	}
}
