package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	ARTIFACTORY_SERVER       string
	ARTIFACTORY_USER         string
	ARTIFACTORY_PASS         string
	ARTIFACTORY_TOKEN        string
	ARTIFACTORY_REPOSITORY   string
	ARTIFACTORY_REPOSITORIES string
	ARTIFACTORY_DOCKER       string
	ARTIFACTORY_WORKERS      int
	ARTIFACTORY_API_URL      = "artifactory/api"
	ARTIFACTORY_ARTIFACT_URL = "artifactory"
	ARTIFACTORY_CLIENT       ArtifactoryClient
)

type ArtifactoryClient struct {
	Client *http.Client
}

type ArtifactoryRepoResults struct {
	Key         string `json:"key"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	PackageType string `json:"packageType"`
}

type ArtifactoryFilesResults struct {
	Repo         string                `json:"repo"`
	Path         string                `json:"path"`
	Created      string                `json:"created"`
	LastModified string                `json:"lastModified"`
	LastUpdated  string                `json:"lastUpdated"`
	Children     []ArtifactoryRepoFile `json:"children"`
	URI          string                `json:"uri"`
}

type ArtifactoryRepoFile struct {
	URI    string `json:"uri"`
	Folder bool   `json:"folder"`
}

type DownloadRequest struct {
	Outdir  string
	Outpath string
	URL     string
}

type ArtifactoryManifestsResults struct {
	Results []ArtifactoryManifestURI `json:"results"`
}

type ArtifactoryManifestURI struct {
	URI string `json:"uri"`
}

func NewArtifactoryClient(cmd *cobra.Command, args []string) {
	ARTIFACTORY_SERVER = strings.TrimSuffix(ARTIFACTORY_SERVER, "/")

	client, err := NewHttpClient()
	if err != nil {
		log.Fatal(err)
	}

	ARTIFACTORY_CLIENT = ArtifactoryClient{Client: client}
}

func (ac *ArtifactoryClient) ListRepositories() ([]ArtifactoryRepoResults, error) {
	var repos []ArtifactoryRepoResults

	endpoint := fmt.Sprintf("%s/%s/repositories", ARTIFACTORY_SERVER, ARTIFACTORY_API_URL)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return repos, fmt.Errorf("error creating GET request - err: %v", err)
	}

	rsp, err := ac.Client.Do(req)
	if err != nil {
		return repos, fmt.Errorf("error in GET response - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return repos, fmt.Errorf("error reading GET response - err: %v", err)
	}

	if err := json.Unmarshal(data, &repos); err != nil {
		return repos, fmt.Errorf("error during JSON Unmarshal - err: %v", err)
	}

	return repos, nil
}

func (ac *ArtifactoryClient) ListRepoFiles(key string, depth int) error {
	endpoint := fmt.Sprintf("%s/%s/storage/%s", ARTIFACTORY_SERVER, ARTIFACTORY_API_URL, key)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("error creating GET request - err: %v", err)
	}

	rsp, err := ac.Client.Do(req)
	if err != nil {
		return fmt.Errorf("error in GET response - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return fmt.Errorf("error reading GET response - err: %v", err)
	}

	var result ArtifactoryFilesResults
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("error during JSON Unmarshal - err: %v", err)
	}

	for _, c := range result.Children {
		fmt.Printf("%s|-- %s\n", strings.Repeat("|   ", depth), c.URI)
		if c.Folder {
			ac.ListRepoFiles(fmt.Sprintf("%s%s", key, c.URI), depth+1)
		}
	}

	return nil
}

func (ac *ArtifactoryClient) DownloadArtifacts(key string, files chan []string) error {
	endpoint := fmt.Sprintf("%s/%s/storage/%s", ARTIFACTORY_SERVER, ARTIFACTORY_API_URL, key)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("error creating GET request - err: %v", err)
	}

	rsp, err := ac.Client.Do(req)
	if err != nil {
		return fmt.Errorf("error in GET response - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return fmt.Errorf("error reading GET response - err: %v", err)
	}

	var result ArtifactoryFilesResults
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("error during JSON Unmarshal - err: %v", err)
	}

	for _, c := range result.Children {
		if c.Folder {
			ac.DownloadArtifacts(fmt.Sprintf("%s%s", key, c.URI), files)
		} else {
			info := []string{
				key,
				c.URI,
			}

			files <- info
		}
	}

	return nil
}

func (ac *ArtifactoryClient) DownloadWorker(files chan []string, wg *sync.WaitGroup) error {
	defer wg.Done()

	for f := range files {
		key := f[0]
		uri := f[1]

		outdir := fmt.Sprintf("%s/%s", ARTIFACTORY_REPOSITORIES, key)
		os.MkdirAll(outdir, os.ModePerm)

		outpath := fmt.Sprintf("%s/%s", outdir, uri)
		downloadUrl := fmt.Sprintf("%s/%s/%s%s", ARTIFACTORY_SERVER, ARTIFACTORY_ARTIFACT_URL, key, uri)

		req, err := http.NewRequest("GET", downloadUrl, nil)
		if err != nil {
			return fmt.Errorf("error creating GET request - err: %v", err)
		}

		rsp, err := ac.Client.Do(req)
		if err != nil {
			return fmt.Errorf("error in GET response - err: %v", err)
		}
		defer rsp.Body.Close()

		data, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			return fmt.Errorf("error reading GET response - err: %v", err)
		}

		if err := ioutil.WriteFile(outpath, data, 0644); err != nil {
			return fmt.Errorf("error saving file - err: %v", err)
		}

		log.Printf("Download finished - URL: %s", downloadUrl)
	}

	return nil
}

func (ac *ArtifactoryClient) GetDockerManifests(repo string) (ArtifactoryManifestsResults, error) {
	var manifests ArtifactoryManifestsResults

	endpoint := fmt.Sprintf("%s/%s/search/artifact?name=manifest.json&repos=%s", ARTIFACTORY_SERVER, ARTIFACTORY_API_URL, ARTIFACTORY_REPOSITORY)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return manifests, fmt.Errorf("error creating get request - err: %v", err)
	}

	rsp, err := ac.Client.Do(req)
	if err != nil {
		return manifests, fmt.Errorf("error sending request - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return manifests, fmt.Errorf("error reading response - err: %v", err)
	}

	if err := json.Unmarshal(data, &manifests); err != nil {
		return manifests, fmt.Errorf("error during json unmarshal - err: %v", err)
	}

	return manifests, nil
}

func (ac *ArtifactoryClient) GetArtifactoryDockerV2(key string, path string) error {
	endpoint := fmt.Sprintf("%s/ui/api/v1/ui/views/dockerv2", ARTIFACTORY_SERVER)

	values := map[string]string{
		"repoKey": key,
		"path":    path,
		"view":    "dockerv2",
	}

	params_buffer := new(bytes.Buffer)
	json.NewEncoder(params_buffer).Encode(values)

	req, err := http.NewRequest("POST", endpoint, params_buffer)
	if err != nil {
		return fmt.Errorf("error creating GET request - err: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	rsp, err := ac.Client.Do(req)
	if err != nil {
		return fmt.Errorf("error in GET response - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return fmt.Errorf("error reading GET response - err: %v", err)
	}

	outdir := fmt.Sprintf("%s/%s/%s", ARTIFACTORY_DOCKER, key, path)
	os.MkdirAll(outdir, os.ModePerm)

	outpath := fmt.Sprintf("%s/dockerv2.json", outdir)
	if err := os.WriteFile(outpath, data, 0644); err != nil {
		return fmt.Errorf("error saving file - err: %v", err)
	}

	log.Printf("[Artifactory] Download finished: %s", path)

	return nil
}

var artifactoryCmd = &cobra.Command{
	Use:   "artifactory",
	Short: "Interact with JFrog Artifactory",
	Long:  `Interact with JFrog Artifactory`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

var artifactoryListRepositories = &cobra.Command{
	Use:    "list-repositories",
	Short:  "List Repositories",
	Long:   "List Repositories",
	PreRun: NewArtifactoryClient,
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("[Artifactory] Listing repositories")
		repos, err := ARTIFACTORY_CLIENT.ListRepositories()
		if err != nil {
			log.Fatal(err)
		}

		header := table.Row{"KEY", "TYPE", "PACKAGE TYPE", "URL"}
		rows := []table.Row{}

		for _, r := range repos {
			rows = append(rows, table.Row{
				r.Key,
				r.Type,
				r.PackageType,
				r.URL,
			})
		}

		CreateTable(header, rows)
	},
}

var artifactoryListFiles = &cobra.Command{
	Use:    "list-files",
	Short:  "List Files from repositories",
	Long:   "List Files from repositories",
	PreRun: NewArtifactoryClient,
	Run: func(cmd *cobra.Command, args []string) {
		var repositories []string

		if len(ARTIFACTORY_REPOSITORY) > 0 {
			repositories = append(repositories, ARTIFACTORY_REPOSITORY)
		} else {
			repos, err := ARTIFACTORY_CLIENT.ListRepositories()
			if err != nil {
				log.Fatal(err)
			}

			for _, r := range repos {
				if strings.Compare(r.Type, "LOCAL") == 0 {
					repositories = append(repositories, r.Key)
				}
			}
		}

		for _, repo := range repositories {
			log.Infof("[Artifactory] Listing files from: %s", repo)
			if err := ARTIFACTORY_CLIENT.ListRepoFiles(repo, 0); err != nil {
				log.Error(err)
			}
			fmt.Println("")
		}
	},
}

var artifactoryDownloadFiles = &cobra.Command{
	Use:    "download-files",
	Short:  "Download Files from a Repository",
	Long:   "Download Files from a Repository",
	PreRun: NewArtifactoryClient,
	Run: func(cmd *cobra.Command, args []string) {
		log.Infof("[Artifactory] Downloading files from: %s", ARTIFACTORY_REPOSITORY)

		var wg sync.WaitGroup
		wg.Add(ARTIFACTORY_WORKERS)

		files := make(chan []string)
		for w := 0; w < ARTIFACTORY_WORKERS; w++ {
			go ARTIFACTORY_CLIENT.DownloadWorker(files, &wg)
		}

		if err := ARTIFACTORY_CLIENT.DownloadArtifacts(ARTIFACTORY_REPOSITORY, files); err != nil {
			log.Fatal(err)
		}

		close(files)
		wg.Wait()
	},
}

var artifactoryDockerInfo = &cobra.Command{
	Use:    "download-docker-info",
	Short:  "Download info about docker images",
	Long:   "Download info about docker images",
	PreRun: NewArtifactoryClient,
	Run: func(cmd *cobra.Command, args []string) {
		log.Infof("[Artifactory] Listing docker manifests - Repository: %s", ARTIFACTORY_REPOSITORY)

		manifests, err := ARTIFACTORY_CLIENT.GetDockerManifests(ARTIFACTORY_REPOSITORY)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("[Artifactory] Total of manifests found: %d", len(manifests.Results))

		for _, manifest := range manifests.Results {
			log.Printf("[Artifactory] Found docker manifest: %s", manifest.URI)

			pattern := "/artifactory/api/storage/" + ARTIFACTORY_REPOSITORY + "/(.+?)/manifest.json"
			r := regexp.MustCompile(pattern)
			matches := r.FindAllStringSubmatch(manifest.URI, -1)

			for _, m := range matches {
				path := strings.ToLower(m[1])
				if err := ARTIFACTORY_CLIENT.GetArtifactoryDockerV2(ARTIFACTORY_REPOSITORY, path); err != nil {
					log.Error(err)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(artifactoryCmd)

	artifactoryCmd.AddCommand(artifactoryListRepositories)
	artifactoryCmd.AddCommand(artifactoryListFiles)
	artifactoryCmd.AddCommand(artifactoryDownloadFiles)
	artifactoryCmd.AddCommand(artifactoryDockerInfo)

	artifactoryCmd.PersistentFlags().StringVarP(&ARTIFACTORY_SERVER, "server", "s", "", "Server Address")
	artifactoryCmd.PersistentFlags().StringVarP(&ARTIFACTORY_USER, "user", "u", "", "Username")
	artifactoryCmd.PersistentFlags().StringVarP(&ARTIFACTORY_PASS, "password", "p", "", "Password")
	artifactoryCmd.PersistentFlags().StringVarP(&ARTIFACTORY_TOKEN, "token", "t", "", "Token")

	artifactoryListFiles.PersistentFlags().StringVarP(&ARTIFACTORY_REPOSITORY, "repository", "r", "", "Repository Name")
	artifactoryDownloadFiles.PersistentFlags().StringVarP(&ARTIFACTORY_REPOSITORY, "repository", "r", "", "Repository Name")
	artifactoryDockerInfo.PersistentFlags().StringVarP(&ARTIFACTORY_REPOSITORY, "repository", "r", "", "Repository Name")

	var err error

	if ARTIFACTORY_REPOSITORIES, err = GetConfigParam("artifactory.repositories"); err != nil {
		log.Fatal(err)
	}

	if ARTIFACTORY_DOCKER, err = GetConfigParam("artifactory.docker"); err != nil {
		log.Fatal(err)
	}

	if ARTIFACTORY_WORKERS, err = GetConfigParamInt("artifactory.workers"); err != nil {
		log.Fatal(err)
	}
}
