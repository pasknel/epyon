package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/bndr/gojenkins"
	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	JENKINS_USERNAME  string
	JENKINS_PASSWORD  string
	JENKINS_SERVER    string
	JENKINS_TOKEN     string
	JENKINS_ARTIFACTS string
	JENKINS_OUTPUTS   string
	J                 JenkinsClient
)

type JenkinsClient struct {
	jenkins *gojenkins.Jenkins
	ctx     context.Context
}

type People struct {
	P []Person `json:"users"`
}

type Person struct {
	U User `json:"user"`
}

type User struct {
	URL  string `json:"absoluteUrl"`
	Name string `json:"fullName"`
}

func NewJenkinsClient(cmd *cobra.Command, args []string) {
	var client JenkinsClient

	ctx := context.Background()

	if len(JENKINS_TOKEN) > 0 {
		JENKINS_PASSWORD = JENKINS_TOKEN
	}

	custom_client, err := NewHttpClient()
	if err != nil {
		log.Fatal(err)
	}

	jenkins := gojenkins.CreateJenkins(custom_client, JENKINS_SERVER, JENKINS_USERNAME, JENKINS_PASSWORD)

	_, err = jenkins.Init(ctx)
	if err != nil {
		log.Fatal(err)
	}

	client.jenkins = jenkins
	client.ctx = ctx

	J = client
}

func (j *JenkinsClient) ListJobs() error {
	log.Infof("[Jenkins] Server: %s - Listing jobs", JENKINS_SERVER)

	jobs, err := j.jenkins.GetAllJobs(j.ctx)
	if err != nil {
		return fmt.Errorf("error listing jobs - err: %v", err)
	}

	resultados := []table.Row{}
	for _, j := range jobs {
		resultados = append(resultados, table.Row{j.GetName(), j.Raw.URL, j.Raw.Description})
	}

	CreateTable(
		table.Row{"NAME", "URL", "DESCRIPTION"},
		resultados,
	)

	return nil
}

func (j *JenkinsClient) PopulateJobsChan(job *gojenkins.Job, builds_chan chan *gojenkins.Build) {
	innerJobs, _ := job.GetInnerJobs(j.ctx)
	if len(innerJobs) > 0 {
		for _, ij := range innerJobs {
			j.PopulateJobsChan(ij, builds_chan)
		}
	} else {
		lastBuild, err := job.GetLastBuild(j.ctx)
		if err != nil {
			log.Errorf("error getting last build - err: %v", err)
			return
		}
		builds_chan <- lastBuild
	}
}

func (j *JenkinsClient) DownloadArtifactsWorker(wg *sync.WaitGroup, builds chan *gojenkins.Build) {
	defer wg.Done()

	for build := range builds {
		jobName := build.Job.GetName()
		buildNumber := build.GetBuildNumber()

		url := strings.Split(build.Job.Raw.URL, "/job/")
		outputDir := fmt.Sprintf("%s/%s%d", JENKINS_ARTIFACTS, strings.Join(url[1:], "/"), buildNumber)
		err := os.MkdirAll(outputDir, 0777)
		if err != nil {
			log.Errorf("err: %s", err)
			continue
		}

		artifacts := build.GetArtifacts()

		if len(artifacts) > 0 {
			log.Infof("Job: %s - Build: %d - Number of Artifacts: %d", jobName, buildNumber, len(artifacts))
			for _, art := range artifacts {
				_, err := art.SaveToDir(j.ctx, outputDir)
				if err != nil {
					log.Errorf("err: %s", err)
					continue
				}
				log.Printf("Artifact downloaded: %s", art.FileName)
			}
		}
	}
}

func (j *JenkinsClient) DownloadArtifacts() error {
	root_jobs, err := j.jenkins.GetAllJobs(j.ctx)
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	routines := 10

	var wg sync.WaitGroup
	wg.Add(routines)

	builds_chan := make(chan *gojenkins.Build)

	for i := 0; i < routines; i++ {
		go j.DownloadArtifactsWorker(&wg, builds_chan)
	}

	for _, job := range root_jobs {
		j.PopulateJobsChan(job, builds_chan)
	}

	close(builds_chan)
	wg.Wait()

	return nil
}

func (j *JenkinsClient) ListUsers() error {
	log.Printf("[Jenkins] Server: %s - Listing Users", JENKINS_SERVER)

	client, err := NewHttpClient()
	if err != nil {
		log.Error(err)
	}

	endpoint := fmt.Sprintf("%s/asynchPeople/api/json?depth=1", JENKINS_SERVER)

	r, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	r.SetBasicAuth(JENKINS_USERNAME, JENKINS_PASSWORD)

	resp, err := client.Do(r)
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	var people People
	err = json.Unmarshal(data, &people)
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	results := []table.Row{}
	for _, p := range people.P {
		results = append(results, table.Row{p.U.Name, p.U.URL})
	}

	headers := table.Row{"NAME", "URL"}
	CreateTable(headers, results)

	return nil
}

func (j *JenkinsClient) OutputWorker(wg *sync.WaitGroup, builds chan *gojenkins.Build) {
	defer wg.Done()

	for build := range builds {
		jobName := build.Job.GetName()
		buildNumber := build.GetBuildNumber()

		url := strings.Split(build.Job.Raw.URL, "/job/")
		outputDir := fmt.Sprintf("%s/%s%d", JENKINS_OUTPUTS, strings.Join(url[1:], "/"), buildNumber)

		err := os.MkdirAll(outputDir, 0777)
		if err != nil {
			log.Errorf("error creating directory - err: %s", err)
			continue
		}

		log.Infof("Getting output - Jobs: %s - Build: %d", jobName, buildNumber)

		output := build.GetConsoleOutput(j.ctx)

		path := fmt.Sprintf("%s/%s/%d/output.txt", JENKINS_OUTPUTS, strings.Join(url[1:], "/"), buildNumber)
		err = ioutil.WriteFile(path, []byte(output), 0644)
		if err != nil {
			log.Errorf("error getting output from build %d - job: %s - err: %s", buildNumber, jobName, err)
			continue
		}

		log.Infof("Output obtained successfully - Job: %s - Build: %d", jobName, buildNumber)
	}
}

func (j *JenkinsClient) GetInnerJobs(job *gojenkins.Job, builds_chan chan *gojenkins.Build) {
	innerJobs, _ := job.GetInnerJobs(j.ctx)
	if len(innerJobs) > 0 {
		for _, ij := range innerJobs {
			j.GetInnerJobs(ij, builds_chan)
		}
	} else {
		lastBuild, err := job.GetLastBuild(j.ctx)
		if err != nil {
			log.Errorf("error getting last build - err: %v", err)
			return
		}

		builds_chan <- lastBuild
	}
}

func (j *JenkinsClient) GetOutputs() error {
	root_jobs, err := j.jenkins.GetAllJobs(j.ctx)
	if err != nil {
		return fmt.Errorf("error listing jobs - err: %v", err)
	}

	total := 10

	var wg sync.WaitGroup
	wg.Add(total)

	builds_chan := make(chan *gojenkins.Build)
	for i := 0; i < total; i++ {
		go j.OutputWorker(&wg, builds_chan)
	}

	for _, job := range root_jobs {
		j.GetInnerJobs(job, builds_chan)
	}

	close(builds_chan)
	wg.Wait()

	return nil
}

var jenkinsListJobsCmd = &cobra.Command{
	Use:    "list-jobs",
	Short:  "List Jenkins jobs",
	Long:   `List Jenkins jobs`,
	PreRun: NewJenkinsClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := J.ListJobs()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var jenkinsListUsersCmd = &cobra.Command{
	Use:    "list-users",
	Short:  "List Jenkins users",
	Long:   `List Jenkins users`,
	PreRun: NewJenkinsClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := J.ListUsers()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var jenkinsDownloadArtifactsCmd = &cobra.Command{
	Use:    "download-artifacts",
	Short:  "Download artifacts from builds",
	Long:   `Download artifacts from builds`,
	PreRun: NewJenkinsClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := J.DownloadArtifacts()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var jenkinsGetOutputsCmd = &cobra.Command{
	Use:    "get-outputs",
	Short:  "Get output from latest builds",
	Long:   `Get output from latest builds`,
	PreRun: NewJenkinsClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := J.GetOutputs()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var jenkinsCmd = &cobra.Command{
	Use:   "jenkins",
	Short: "Interact with Jenkins Server",
	Long:  `Options for Jenkins Interaction`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

func init() {
	rootCmd.AddCommand(jenkinsCmd)

	jenkinsCmd.AddCommand(jenkinsListJobsCmd)
	jenkinsCmd.AddCommand(jenkinsListUsersCmd)
	jenkinsCmd.AddCommand(jenkinsDownloadArtifactsCmd)
	jenkinsCmd.AddCommand(jenkinsGetOutputsCmd)

	jenkinsCmd.PersistentFlags().StringVarP(&JENKINS_SERVER, "server", "s", "", "Server Address")
	jenkinsCmd.PersistentFlags().StringVarP(&JENKINS_USERNAME, "user", "u", "", "Username")
	jenkinsCmd.PersistentFlags().StringVarP(&JENKINS_PASSWORD, "password", "p", "", "Password")
	jenkinsCmd.PersistentFlags().StringVarP(&JENKINS_TOKEN, "token", "t", "", "Access Token")

	var err error

	JENKINS_ARTIFACTS, err = GetConfigParam("jenkins.artifacts")
	if err != nil {
		log.Fatal(err)
	}

	JENKINS_OUTPUTS, err = GetConfigParam("jenkins.outputs")
	if err != nil {
		log.Fatal(err)
	}
}
