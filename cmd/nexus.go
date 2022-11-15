package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	NEXUS_SERVER          string
	NEXUS_USER            string
	NEXUS_PASSWORD        string
	NEXUS_TOKEN           string
	NEXUS_REPOSITORY_NAME string
	NEXUS_OUTDIR          string
	NEXUS_WORKERS         = 10
)

type NexusRepoSearch struct {
	Name   string `json:"name"`
	Format string `json:"format"`
	Type   string `json:"type"`
	URL    string `json:"url"`
}

type NexusAssetItem struct {
	DownloadUrl string `json:"downloadUrl"`
	Path        string `json:"path"`
	Id          string `json:"id"`
	Repository  string `json:"repository"`
	Format      string `json:"format"`
	ContentType string `json:"contentType"`
	FileSize    int    `json:"fileSize"`
	BlobCreated string `json:"blobCreated"`
}

type NexusComponentItem struct {
	Id         string           `json:"id"`
	Repository string           `json:"repository"`
	Format     string           `json:"format"`
	Name       string           `json:"name"`
	Version    string           `json:"version"`
	Assets     []NexusAssetItem `json:"assets"`
}

type NexusComponentSearch struct {
	Items             []NexusComponentItem `json:"items"`
	ContinuationToken string               `json:"continuationToken"`
}

type NexusDownloadRequest struct {
	Repo        string
	Component   string
	Version     string
	AssetPath   string
	DownloadURL string
}

func NexusGetRepoList() ([]NexusRepoSearch, error) {
	results := []NexusRepoSearch{}

	client, err := NewHttpClient()
	if err != nil {
		return results, err
	}

	endpoint := fmt.Sprintf("%s/service/rest/v1/repositories", strings.TrimSuffix(NEXUS_SERVER, "/"))

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return results, fmt.Errorf("error creating GET request - err: %v", err)
	}

	if len(NEXUS_USER) > 0 {
		req.SetBasicAuth(NEXUS_USER, NEXUS_PASSWORD)
	}

	rsp, err := client.Do(req)
	if err != nil {
		return results, fmt.Errorf("error in GET request - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return results, fmt.Errorf("error reading data - err: %v", err)
	}

	err = json.Unmarshal(data, &results)
	if err != nil {
		return results, fmt.Errorf("error in JSON Unmarshal - err: %v", err)
	}

	if VERBOSE {
		for _, r := range results {
			log.WithFields(log.Fields{
				"name":   r.Name,
				"format": r.Format,
				"url":    r.URL,
			}).Info("repository found")
		}
	}

	return results, nil
}

func NexusGetComponentList(repository string) ([]NexusComponentItem, error) {
	components := []NexusComponentItem{}

	client, err := NewHttpClient()
	if err != nil {
		return components, err
	}

	endpoint := fmt.Sprintf("%s/service/rest/v1/components?repository=%s", strings.TrimSuffix(NEXUS_SERVER, "/"), repository)

	for {
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return components, fmt.Errorf("error creating GET request - err: %v", err)
		}

		if len(NEXUS_USER) > 0 {
			req.SetBasicAuth(NEXUS_USER, NEXUS_PASSWORD)
		}

		rsp, err := client.Do(req)
		if err != nil {
			return components, fmt.Errorf("error in GET request - err: %v", err)
		}
		defer rsp.Body.Close()

		data, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			return components, fmt.Errorf("error reading data - err: %v", err)
		}

		var results NexusComponentSearch
		err = json.Unmarshal(data, &results)
		if err != nil {
			return components, fmt.Errorf("error in JSON Unmarshal - err: %v", err)
		}

		for _, r := range results.Items {
			components = append(components, r)
			if VERBOSE {
				log.WithFields(log.Fields{
					"name":       r.Name,
					"repository": r.Repository,
					"version":    r.Version,
				}).Info("component found")
			}
		}

		if len(results.ContinuationToken) == 0 {
			break
		} else {
			endpoint = fmt.Sprintf("%s/service/rest/v1/components?repository=%s&continuationToken=%s", NEXUS_SERVER, repository, results.ContinuationToken)
		}
	}

	return components, nil
}

func NexusListRepositories() error {
	results, err := NexusGetRepoList()
	if err != nil {
		return err
	}

	header := table.Row{"NAME", "FORMAT", "TYPE", "URL"}
	rows := []table.Row{}

	for _, r := range results {
		rows = append(rows, table.Row{
			r.Name,
			r.Format,
			r.Type,
			r.URL,
		})
	}

	CreateTable(header, rows)

	return nil
}

func NexusListComponents() error {
	var repos []NexusRepoSearch
	var err error

	if len(NEXUS_REPOSITORY_NAME) > 0 {
		repos = append(repos, NexusRepoSearch{
			Name: NEXUS_REPOSITORY_NAME,
		})
	} else {
		repos, err = NexusGetRepoList()
		if err != nil {
			return err
		}
	}

	for _, r := range repos {
		log.Printf("Listing components of repository: %s", r.Name)

		components, err := NexusGetComponentList(r.Name)
		if err != nil {
			log.Error(err)
			continue
		}

		header := table.Row{"ID", "REPOSITORY", "FORMAT", "NAME", "VERSION"}
		rows := []table.Row{}

		for _, c := range components {
			rows = append(rows, table.Row{
				c.Id,
				c.Repository,
				c.Format,
				c.Name,
				c.Version,
			})
		}

		CreateTable(header, rows)
		fmt.Println()
	}

	return nil
}

func NexusListAssets() error {
	var repos []NexusRepoSearch
	var err error

	if len(NEXUS_REPOSITORY_NAME) > 0 {
		repos = append(repos, NexusRepoSearch{
			Name: NEXUS_REPOSITORY_NAME,
		})
	} else {
		repos, err = NexusGetRepoList()
		if err != nil {
			return err
		}
	}

	for _, r := range repos {
		components, err := NexusGetComponentList(r.Name)
		if err != nil {
			log.Error(err)
			continue
		}

		for _, c := range components {
			log.Infof("Listing assets of repository: %s / component: %s", r.Name, c.Name)

			header := table.Row{"REPOSITORY", "COMPONENT", "VERSION", "PATH", "FILE SIZE"}
			rows := []table.Row{}

			for _, asset := range c.Assets {
				rows = append(rows, table.Row{
					r.Name,
					c.Name,
					c.Version,
					asset.Path,
					asset.FileSize,
				})

				if VERBOSE {
					log.WithFields(log.Fields{
						"path":       asset.Path,
						"component":  c.Name,
						"repository": r.Name,
						"version":    c.Version,
					}).Info("asset found")
				}
			}

			CreateTable(header, rows)
			fmt.Println()
		}
	}

	return nil
}

func NexusDownloadWorker(wg *sync.WaitGroup, downloads chan NexusDownloadRequest) {
	defer wg.Done()

	for d := range downloads {
		client, err := NewHttpClient()
		if err != nil {
			log.Error(err)
			continue
		}

		req, err := http.NewRequest("GET", d.DownloadURL, nil)
		if err != nil {
			log.Error(fmt.Errorf("error creating GET request - err: %v", err))
			continue
		}

		if len(NEXUS_USER) > 0 {
			req.SetBasicAuth(NEXUS_USER, NEXUS_PASSWORD)
		}

		rsp, err := client.Do(req)
		if err != nil {
			log.Error(fmt.Errorf("error in GET request - err: %v", err))
			continue
		}
		defer rsp.Body.Close()

		outdir := fmt.Sprintf("%s/%s/%s/%s", NEXUS_OUTDIR, d.Repo, d.Component, d.Version)
		fileName := d.AssetPath
		p := strings.Split(d.AssetPath, "/")

		if len(p) > 1 {
			outdir = fmt.Sprintf("%s/%s", outdir, strings.Join(p[:len(p)-1], "/"))
			fileName = p[len(p)-1]
		}
		os.MkdirAll(outdir, os.ModePerm)

		outfile := fmt.Sprintf("%s/%s", outdir, fileName)
		out, err := os.Create(outfile)
		if err != nil {
			log.Error(fmt.Errorf("error creating file - err: %v", err))
			continue
		}
		defer out.Close()

		_, err = io.Copy(out, rsp.Body)
		if err != nil {
			log.Error(fmt.Errorf("error saving file - err: %v", err))
			continue
		}

		log.WithFields(log.Fields{
			"file": outfile,
		}).Info("download finished")
	}
}

func NexusDownloadAssets() error {
	os.MkdirAll(NEXUS_OUTDIR, os.ModePerm)

	var repos []NexusRepoSearch
	var err error

	if len(NEXUS_REPOSITORY_NAME) > 0 {
		repos = append(repos, NexusRepoSearch{
			Name: NEXUS_REPOSITORY_NAME,
		})
	} else {
		repos, err = NexusGetRepoList()
		if err != nil {
			return err
		}
	}

	var wg sync.WaitGroup
	wg.Add(NEXUS_WORKERS)

	downloads := make(chan NexusDownloadRequest)

	for w := 0; w < NEXUS_WORKERS; w++ {
		go NexusDownloadWorker(&wg, downloads)
	}

	for _, r := range repos {
		components, err := NexusGetComponentList(r.Name)
		if err != nil {
			log.Error(err)
			continue
		}

		for _, c := range components {
			log.Infof("Downloading assets of repository: %s / component: %s", r.Name, c.Name)

			for _, asset := range c.Assets {
				if VERBOSE {
					log.WithFields(log.Fields{
						"repo":        r.Name,
						"component":   c.Name,
						"version":     c.Version,
						"downloadURL": asset.DownloadUrl,
					}).Info("asset found")
				}

				downloads <- NexusDownloadRequest{
					Repo:        r.Name,
					Component:   c.Name,
					Version:     c.Version,
					DownloadURL: asset.DownloadUrl,
					AssetPath:   asset.Path,
				}
			}
		}
	}

	close(downloads)
	wg.Wait()

	return nil
}

var nexusListRepositoriesCmd = &cobra.Command{
	Use:   "list-repositories",
	Short: "List Nexus Repositories",
	Long:  `List Nexus Repositories`,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Nexus] Listing repositories")

		err := NexusListRepositories()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var nexusListComponentsCmd = &cobra.Command{
	Use:   "list-components",
	Short: "List Nexus Components",
	Long:  `List Nexus Components`,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Nexus] Listing components")

		err := NexusListComponents()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var nexusListAssetsCmd = &cobra.Command{
	Use:   "list-assets",
	Short: "List Nexus Assets",
	Long:  `List Nexus Assets`,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Nexus] Listing assets")

		err := NexusListAssets()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var nexusDownloadAssetsCmd = &cobra.Command{
	Use:   "download-assets",
	Short: "Download Nexus Assets",
	Long:  `Download Nexus Assets`,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Nexus] Downloading assets")

		err := NexusDownloadAssets()
		if err != nil {
			log.Fatal(err)
		}

	},
}

var nexusCmd = &cobra.Command{
	Use:   "nexus",
	Short: "Interact with Nexus Repository",
	Long:  `Options for Nexus Interaction`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

func init() {
	rootCmd.AddCommand(nexusCmd)

	nexusCmd.AddCommand(nexusListRepositoriesCmd)
	nexusCmd.AddCommand(nexusListComponentsCmd)
	nexusCmd.AddCommand(nexusListAssetsCmd)
	nexusCmd.AddCommand(nexusDownloadAssetsCmd)

	nexusCmd.PersistentFlags().StringVarP(&NEXUS_SERVER, "server", "s", "", "Server Address")
	nexusCmd.PersistentFlags().StringVarP(&NEXUS_USER, "user", "u", "", "Username")
	nexusCmd.PersistentFlags().StringVarP(&NEXUS_PASSWORD, "password", "p", "", "Password")
	nexusCmd.PersistentFlags().StringVarP(&NEXUS_TOKEN, "token", "t", "", "Access Token")

	nexusListComponentsCmd.Flags().StringVarP(&NEXUS_REPOSITORY_NAME, "repository", "r", "", "Repository Name")
	nexusListAssetsCmd.Flags().StringVarP(&NEXUS_REPOSITORY_NAME, "repository", "r", "", "Repository Name")
	nexusDownloadAssetsCmd.Flags().StringVarP(&NEXUS_REPOSITORY_NAME, "repository", "r", "", "Repository Name")
	nexusDownloadAssetsCmd.Flags().IntVarP(&NEXUS_WORKERS, "workers", "w", 10, "Total of workers")

	var err error

	if NEXUS_OUTDIR, err = GetConfigParam("nexus.repositories"); err != nil {
		log.Fatal(err)
	}
}
