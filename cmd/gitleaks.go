package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	GITLEAKS_PROJECT string
	GITLEAKS_PATH    string
	GITLEAKS_REPORT  = "gitleaks-report.json"
	GITLEAKS_ISSUES  = "gitleaks-issues.json"
)

type GitleaksJson struct {
	Description string  `json:"Description"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	StartColumn int     `json:"StartColumn"`
	EndColumn   int     `json:"EndColumn"`
	Match       string  `json:"Match"`
	Secret      string  `json:"Secret"`
	File        string  `json:"File"`
	Commit      string  `json:"Commit"`
	Entropy     float64 `json:"Entropy"`
	Author      string  `json:"Author"`
	Email       string  `json:"Email"`
	Date        string  `json:"Date"`
	Message     string  `json:"Message"`
	RuleID      string  `json:"RuleID"`
}

type GitleaksResults struct {
	Project string
	Issues  []GitleaksJson
}

func RunGitleaks(path string) error {
	log.Printf("[Gitleaks] Scanning project: %s", path)

	cmd := exec.Command(GITLEAKS_PATH, "detect", "--source", path, "-r", GITLEAKS_REPORT)
	err := cmd.Run()

	report, err := os.Open(GITLEAKS_REPORT)
	if os.IsNotExist(err) {
		return fmt.Errorf("nothing found with gitleaks")
	}
	defer report.Close()

	data, err := ioutil.ReadAll(report)
	if err != nil {
		return fmt.Errorf("error reading gitleaks report file - err: %v", err)
	}

	info := []GitleaksJson{}
	err = json.Unmarshal(data, &info)
	if err != nil {
		return fmt.Errorf("error in JSON unmarshal - err: %v", err)
	}

	rows := []table.Row{}
	header := table.Row{"DESCRIPTION", "FILE", "COMMIT", "SECRET"}

	for _, i := range info {
		rows = append(rows, table.Row{
			i.Description,
			i.File,
			i.Commit,
			i.Secret,
		})
	}

	if len(rows) > 0 {
		log.Printf("[Gitleaks] Issues found on: %s", path)
		CreateTable(header, rows)
		fmt.Println()

		gr := GitleaksResults{
			Project: path,
			Issues:  info,
		}

		grBytes, err := json.Marshal(gr)
		if err != nil {
			return fmt.Errorf("error in json marshal - err: %v", err)
		}

		logFile, err := os.OpenFile(GITLEAKS_ISSUES, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("error opening json file - err: %v", err)
		}
		defer logFile.Close()

		_, err = logFile.Write(grBytes)
		if err != nil {
			return fmt.Errorf("error saving gitleaks results - err: %v", err)
		}
	}

	report.Close()

	os.Remove(GITLEAKS_REPORT)

	return nil
}

func ScanProjectFolder(projectID string) error {
	projectPath := fmt.Sprintf("%s/%s", GITLEAKS_PROJECT, projectID)

	projectFolder, err := os.Open(projectPath)
	if err != nil {
		return fmt.Errorf("error opening project folder - err: %v", err)

	}
	defer projectFolder.Close()

	projectFiles, err := projectFolder.ReadDir(1)
	if err != nil {
		return fmt.Errorf("error listing project folder - err: %v", err)
	}

	if projectFiles[0].IsDir() {
		path := filepath.Join(projectPath, projectFiles[0].Name())
		if err := RunGitleaks(path); err != nil {
			log.Error(err)
		}
	}

	return nil
}

var gitleaksCmd = &cobra.Command{
	Use:   "gitleaks",
	Short: "Scan projects folders with Gitleaks",
	Long:  `Scan projects folders with Gitleaks`,

	Run: func(cmd *cobra.Command, args []string) {
		rootDir, err := os.Open(GITLEAKS_PROJECT)
		if err != nil {
			log.Fatal(err)
		}
		defer rootDir.Close()

		projectIDs, err := rootDir.ReadDir(0)
		if err != nil {
			log.Fatalf("error listing directory - err: %v", err)
		}

		for _, pid := range projectIDs {
			ScanProjectFolder(pid.Name())
		}
	},
}

func init() {
	rootCmd.AddCommand(gitleaksCmd)

	gitleaksCmd.Flags().StringVarP(&GITLEAKS_PROJECT, "projects", "p", "./gitlab/projects", "Path to Downloaded Projects")

	var err error

	GITLEAKS_PATH, err = GetConfigParam("gitleaks.path")
	if err != nil {
		log.Fatal(err)
	}
}
