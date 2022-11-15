package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	HORUSEC_PROJECTS string
	HORUSEC_PATH     string
	HORUSEC_REPORT   = "horusec-report.json"
)

type Vulnerability struct {
	VulnerabilityID     string   `json:"vulnerabilityID"`
	Line                string   `json:"line"`
	Column              string   `json:"column"`
	Confidence          string   `json:"confidence"`
	File                string   `json:"file"`
	Code                string   `json:"code"`
	Details             string   `json:"details"`
	SecurityTool        string   `json:"securityTool"`
	Language            string   `json:"language"`
	Severity            string   `json:"severity"`
	Type                string   `json:"type"`
	CommitAuthor        string   `json:"commitAuthor"`
	CommitEmail         string   `json:"commitEmail"`
	CommitHash          string   `json:"commitHash"`
	CommitMessage       string   `json:"commitMessage"`
	CommitDate          string   `json:"commitDate"`
	RuleId              string   `json:"rule_id"`
	VulnHash            string   `json:"vulnHash"`
	DeprecatedHashes    []string `json:"deprecatedHashes"`
	SecurityToolVersion string   `json:"securityToolVersion"`
	SecurityToolInfoUri string   `json:"securityToolInfoUri"`
}

type Anylsis struct {
	VulnerabilityID string        `json:"vulnerabilityID"`
	AnalysisID      string        `json:"analysisID"`
	CreatedAt       string        `json:"createdAt"`
	Vulnerabilities Vulnerability `json:"vulnerabilities"`
}

type HorusecReport struct {
	Version                 string    `json:"version"`
	Id                      string    `json:"id"`
	RepositoryID            string    `json:"repositoryID"`
	RepositoryName          string    `json:"repositoryName"`
	WorkspaceID             string    `json:"workspaceID"`
	WorkspaceName           string    `json:"workspaceName"`
	Status                  string    `json:"status"`
	Errors                  string    `json:"errors"`
	CreatedAt               string    `json:"createdAt"`
	FinishedAt              string    `json:"finishedAt"`
	AnalysisVulnerabilities []Anylsis `json:"analysisVulnerabilities"`
}

func SeverityColor(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return Red(severity)
	case "MEDIUM":
		return Yellow(severity)
	case "LOW":
		return Green(severity)
	}
	return severity
}
func HorusecStart(path string) error {
	log.Printf("[Horusec] Starting static analysis on: %s \n", path)

	cmd := exec.Command(HORUSEC_PATH, "start", "-o", "json", "-O", HORUSEC_REPORT, "-p", path)
	cmd.Run()

	report, err := os.Open(HORUSEC_REPORT)
	if os.IsNotExist(err) {
		return fmt.Errorf("nothing found with horusec")
	}
	defer report.Close()

	data, err := ioutil.ReadAll(report)
	if err != nil {
		return fmt.Errorf("error reading horusec report file - err: %v", err)
	}

	var hr HorusecReport
	err = json.Unmarshal(data, &hr)
	if err != nil {
		return fmt.Errorf("error in JSON unmarshal - err: %v", err)
	}

	rows := []table.Row{}
	header := table.Row{"SEVERITY", "LANGUAGE", "TYPE", "FILE", "CODE"}

	for _, av := range hr.AnalysisVulnerabilities {
		rows = append(rows, table.Row{
			SeverityColor(av.Vulnerabilities.Severity),
			av.Vulnerabilities.Language,
			av.Vulnerabilities.Type,
			av.Vulnerabilities.File,
			av.Vulnerabilities.Code,
		})
	}

	if len(rows) > 0 {
		CreateTable(header, rows)
		fmt.Println()
	} else {
		log.Errorf("[Horusec] Nothing found on: %s", path)
	}

	return nil
}

var horusecCmd = &cobra.Command{
	Use:   "horusec",
	Short: "Static source code anylsis with Horusec",
	Long:  `Static source code anylsis with Horusec`,

	Run: func(cmd *cobra.Command, args []string) {
		rootDir, err := os.Open(HORUSEC_PROJECTS)
		if err != nil {
			log.Fatal(err)
		}
		defer rootDir.Close()

		projectIDs, err := rootDir.ReadDir(0)
		if err != nil {
			log.Fatalf("error listing directory - err: %v", err)
		}

		for _, pid := range projectIDs {
			projectPath := fmt.Sprintf("%s/%s", HORUSEC_PROJECTS, pid.Name())
			HorusecStart(projectPath)
			os.Remove(HORUSEC_REPORT)
		}
	},
}

func init() {
	rootCmd.AddCommand(horusecCmd)

	horusecCmd.PersistentFlags().StringVarP(&HORUSEC_PROJECTS, "projects", "p", "", "Path to Downloaded Projects")

	var err error

	HORUSEC_PATH, err = GetConfigParam("horusec.path")
	if err != nil {
		log.Fatal(err)
	}
}
