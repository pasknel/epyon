package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jedib0t/go-pretty/table"
	"github.com/rs/zerolog"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/detect"
)

var (
	GITLEAKS_PROJECT string
)

type GitleaksIssue struct {
	Project     string
	Description string
	File        string
	Commit      string
	Secret      string
}

func SaveGitleakIssues(issue GitleaksIssue) error {
	out, err := os.OpenFile("gitleaks-issues.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	data, err := json.Marshal(issue)
	if err != nil {
		return fmt.Errorf("error during json marshal - err: %v", err)
	}

	out.Write(data)

	return nil
}

func RunGitleaks(path string) error {
	log.Printf("[Gitleaks] Scanning project: %s", path)

	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return fmt.Errorf("error creating gitleaks detector - err: %v", err)
	}

	findings, _ := detector.DetectGit(path, "", detect.DetectType)

	if len(findings) > 0 {
		log.Printf("[Gitleaks] Issues found on: %s", path)

		rows := []table.Row{}
		header := table.Row{"DESCRIPTION", "FILE", "COMMIT", "SECRET"}

		for _, f := range findings {
			issue := GitleaksIssue{
				Project:     path,
				Description: f.Description,
				File:        f.File,
				Commit:      f.Commit,
				Secret:      f.Secret,
			}

			rows = append(rows, table.Row{
				issue.Description,
				issue.File,
				issue.Commit,
				issue.Secret,
			})

			if err := SaveGitleakIssues(issue); err != nil {
				log.Error(err)
			}
		}

		CreateTable(header, rows)
	}

	return nil
}

func ScanProjectFolder(projectID string) error {
	projectPath := fmt.Sprintf("%s/%s", GITLEAKS_PROJECT, projectID)

	projectFolder, err := os.Open(projectPath)
	if err != nil {
		return fmt.Errorf("error opening project folder - err: %v", err)

	}
	defer projectFolder.Close()

	projectFiles, err := projectFolder.ReadDir(0)
	if err != nil {
		return fmt.Errorf("error listing project folder - err: %v", err)
	}

	path := projectPath
	if len(projectFiles) == 1 {
		// Github projects
		if projectFiles[0].IsDir() {
			path = filepath.Join(projectPath, projectFiles[0].Name())
		}
	}

	if err := RunGitleaks(path); err != nil {
		log.Error(err)
	}

	return nil
}

var gitleaksCmd = &cobra.Command{
	Use:   "gitleaks",
	Short: "Scan projects folders with Gitleaks",
	Long:  `Scan projects folders with Gitleaks`,

	Run: func(cmd *cobra.Command, args []string) {
		// Disable debug messages created by gitleaks
		zerolog.SetGlobalLevel(zerolog.Disabled)

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
			if err := ScanProjectFolder(pid.Name()); err != nil {
				log.Error(err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(gitleaksCmd)

	gitleaksCmd.Flags().StringVarP(&GITLEAKS_PROJECT, "projects", "p", "./gitlab/projects", "Path to Downloaded Projects")
}
