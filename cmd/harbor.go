package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	HARBOR_SERVER     string
	HARBOR_USERNAME   string
	HARBOR_PASSWORD   string
	HARBOR_PROJECT    string
	HARBOR_REPOSITORY string
	HARBOR_TAG        string
	HARBOR_PROJECTS   string
	HARBOR_IMAGES     string
	HC                HarborClient
)

type HarborClient struct{}

type HarborCreateUser struct {
	Email    string `json:"email"`
	RealName string `json:"realname"`
	Comment  string `json:"comment"`
	Password string `json:"password"`
	Username string `json:"username"`
}

type HarborCveAllowlist struct {
	CreationTime string `json:"creation_time"`
	ID           int    `json:"id"`
	ProjectID    int    `json:"project_id"`
	UpdateTime   string `json:"update_time"`
}

type HarborProject struct {
	ChartCount   int                   `json:"chart_count"`
	CreationTime string                `json:"creation_time"`
	Metadata     HarborProjectMetadata `json:"metadata"`
	Name         string                `json:"name"`
	OwnerID      int                   `json:"owner_id"`
	OwnerName    string                `json:"owner_name"`
	ProjectID    int                   `json:"project_id"`
	RepoCount    int                   `json:"repo_count"`
	UpdateTime   string                `json:"update_time"`
}

type HarborProjectMetadata struct {
	Public string `json:"public"`
}

type HarborRepository struct {
	ArtifactCount int    `json:"artifact_count"`
	CreationTime  string `json:"creation_time"`
	ID            int    `json:"id"`
	Name          string `json:"name"`
	ProjectID     int    `json:"project_id"`
	PullCount     int    `json:"pull_count"`
	UpdateTime    string `json:"update_time"`
}

type HarborBuildHistory struct {
	Absolute bool   `json:"absolute"`
	Href     string `json:"href"`
}

type HarborAdditionLinks struct {
	BuildHistory HarborBuildHistory `json:"build_history"`
}

type HarborArtifactTags struct {
	ArtifactID   int    `json:"artifact_id"`
	ID           int    `json:"id"`
	Immutable    bool   `json:"immutable"`
	Name         string `json:"name"`
	PullTime     string `json:"pull_time"`
	PushTime     string `json:"push_time"`
	RepositoryID int    `json:"repository_id"`
	Signed       bool   `json:"signed"`
}

type HarborArtifact struct {
	AdditionLinks     HarborAdditionLinks  `json:"addition_links"`
	Digest            string               `json:"digest"`
	ID                int                  `json:"id"`
	ManifestMediaType string               `json:"manifest_media_type"`
	MediaType         string               `json:"media_type"`
	ProjectID         int                  `json:"project_id"`
	PullTime          string               `json:"pull_time"`
	PushTime          string               `json:"push_time"`
	RepositoryID      int                  `json:"repository_id"`
	Size              int                  `json:"size"`
	Tags              []HarborArtifactTags `json:"tags"`
	Type              string               `json:"type"`
}

type HarborBuildCommand struct {
	Created    string `json:"created"`
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer"`
}

type HarborSystemInfo struct {
	AuthMode         string `json:"auth_mode"`
	BannerMessage    string `json:"banner_message"`
	Version          string `json:"harbor_version"`
	PrimaryAuthMode  bool   `json:"primary_auth_mode"`
	SelfRegistration bool   `json:"self_registration"`
}

type HarborServiceToken struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	Expires     int    `json:"expires_in"`
	Issued      string `json:"issued_at"`
}

type HarborManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Layers        []struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	} `json:"layers"`
}

func NewHarborClient(cmd *cobra.Command, args []string) {
	HC = HarborClient{}
}

func (h *HarborClient) CreateAccount() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter username for new account: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSuffix(username, "\n")

	fmt.Printf("Enter password for new account: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSuffix(password, "\n")

	fmt.Printf("Enter name for new account: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSuffix(name, "\n")

	fmt.Printf("Enter email for new account: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSuffix(email, "\n")

	createUser := HarborCreateUser{
		Email:    email,
		RealName: name,
		Comment:  "",
		Password: password,
		Username: username,
	}

	bytesCreateUser, err := json.Marshal(createUser)
	if err != nil {
		return fmt.Errorf("error during json marshal - err: %v", err)
	}

	endpoint := fmt.Sprintf("%s/api/v2.0/users", HARBOR_SERVER)

	client, err := NewHttpClient()
	if err != nil {
		return fmt.Errorf("error creating http client - err: %v", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(bytesCreateUser))
	if err != nil {
		return fmt.Errorf("error creating post request - err: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if len(HARBOR_USERNAME) > 0 {
		req.SetBasicAuth(HARBOR_USERNAME, HARBOR_PASSWORD)
	}

	rsp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending http request - err: %v", err)
	}
	defer rsp.Body.Close()

	log.Printf("status code: %d", rsp.StatusCode)

	return nil
}

func (h *HarborClient) ListSystemInfo() error {
	endpoint := fmt.Sprintf("%s/api/v2.0/systeminfo", HARBOR_SERVER)

	client, err := NewHttpClient()
	if err != nil {
		return fmt.Errorf("error creating http client - err: %v", err)
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("error creating http request - err: %v", err)
	}

	if len(HARBOR_USERNAME) > 0 {
		req.SetBasicAuth(HARBOR_USERNAME, HARBOR_PASSWORD)
	}

	rsp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending http request - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return fmt.Errorf("error reading response - err: %v", err)
	}

	var info HarborSystemInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("error during json unmarshal - err: %v", err)
	}

	header := table.Row{"AUTH MODE", "BANNER MESSAGE", "VERSION", "SELF REGISTRATION"}
	rows := []table.Row{}

	rows = append(rows, table.Row{
		info.AuthMode,
		info.BannerMessage,
		info.Version,
		info.SelfRegistration,
	})

	CreateTable(header, rows)

	return nil
}

func (h *HarborClient) GetBuildHistory(url string) ([]HarborBuildCommand, error) {
	var commands []HarborBuildCommand

	client, err := NewHttpClient()
	if err != nil {
		return commands, fmt.Errorf("error creating http client - err: %v", err)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return commands, fmt.Errorf("error creating http request - err: %v", err)
	}

	if len(HARBOR_USERNAME) > 0 {
		req.SetBasicAuth(HARBOR_USERNAME, HARBOR_PASSWORD)
	}

	rsp, err := client.Do(req)
	if err != nil {
		return commands, fmt.Errorf("error sending http request - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return commands, fmt.Errorf("error reading response - err: %v", err)
	}

	if err := json.Unmarshal(data, &commands); err != nil {
		return commands, fmt.Errorf("error during json unmarshal - err: %v", err)
	}

	return commands, nil
}

func (h *HarborClient) ListBuildCommands() error {
	var Projects []string

	if len(HARBOR_PROJECT) > 0 {
		Projects = append(Projects, HARBOR_PROJECT)
	} else {
		projects, err := h.GetProjectList()
		if err != nil {
			return err
		}

		for _, proj := range projects {
			Projects = append(Projects, proj.Name)
		}
	}

	for _, proj := range Projects {
		var Repositories []string

		if len(HARBOR_REPOSITORY) > 0 {
			Repositories = append(Repositories, HARBOR_REPOSITORY)
		} else {
			repositories, err := h.GetRepositoryList(proj)
			if err != nil {
				return err
			}

			for _, repo := range repositories {
				index := strings.Index(repo.Name, "/") + 1
				Repositories = append(Repositories, repo.Name[index:])
			}
		}

		for _, repo := range Repositories {
			log.Printf("[Harbor] Listing Build Commands - Project: %s - Repository: %s", proj, repo)

			artifacts, err := h.GetArtifactList(proj, repo)
			if err != nil {
				log.Error(err)
				continue
			}

			log.Printf("[Harbor] Project: %s - Repository: %s - Total of artifacts: %d", proj, repo, len(artifacts))

			for _, artifact := range artifacts {
				for _, tag := range artifact.Tags {
					log.Printf("[Harbor] Tag: %s - Digest: %s", tag.Name, artifact.Digest)

					build_history_url := HARBOR_SERVER + artifact.AdditionLinks.BuildHistory.Href

					commands, err := h.GetBuildHistory(build_history_url)
					if err != nil {
						log.Error(err)
						continue
					}

					commandsBytes, err := json.Marshal(commands)
					if err != nil {
						log.Errorf("error during json marshal - err: %v", err)
						continue
					}

					outdir := fmt.Sprintf("%s/%s/repositories/%s/%s", HARBOR_PROJECTS, proj, repo, tag.Name)
					os.MkdirAll(outdir, os.ModePerm)

					commandsFile := fmt.Sprintf("%s/build_history.json", outdir)
					if err := os.WriteFile(commandsFile, commandsBytes, 0644); err != nil {
						log.Errorf("error creating json file - err: %v", err)
						continue
					}

					log.Printf("[Harbor] Build History File Created: %s", commandsFile)
					fmt.Println()
				}
			}
		}
	}

	return nil
}

func (h *HarborClient) ListImages() error {
	var Projects []string

	if len(HARBOR_PROJECT) > 0 {
		Projects = append(Projects, HARBOR_PROJECT)
	} else {
		projects, err := h.GetProjectList()
		if err != nil {
			return err
		}

		for _, proj := range projects {
			Projects = append(Projects, proj.Name)
		}
	}

	for _, proj := range Projects {
		var Repositories []string

		if len(HARBOR_REPOSITORY) > 0 {
			Repositories = append(Repositories, HARBOR_REPOSITORY)
		} else {
			repositories, err := h.GetRepositoryList(proj)
			if err != nil {
				return err
			}

			for _, repo := range repositories {
				index := strings.Index(repo.Name, "/") + 1
				Repositories = append(Repositories, repo.Name[index:])
			}
		}

		for _, repo := range Repositories {
			header := table.Row{"PROJECT", "REPOSITORY", "TAG"}
			rows := []table.Row{}

			artifacts, err := h.GetArtifactList(proj, repo)
			if err != nil {
				log.Errorf("project: %s - repository: %s - %v", proj, repo, err)
				continue
			}

			for _, art := range artifacts {
				for _, t := range art.Tags {
					rows = append(rows, table.Row{proj, repo, t.Name})
				}
			}

			log.Infof("[Harbor] Listing Images - Project: %s - Repository: %s", proj, repo)
			CreateTable(header, rows)
			fmt.Println()
		}

		fmt.Println()
	}

	return nil
}

func (h *HarborClient) GetArtifactList(project string, repository string) ([]HarborArtifact, error) {
	var artifacts []HarborArtifact

	page := 1
	page_size := 100

	client, err := NewHttpClient()
	if err != nil {
		return artifacts, fmt.Errorf("error creating http client - err: %v", err)
	}

	for {
		endpoint := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts?page=%d&page_size=%d", HARBOR_SERVER, project, repository, page, page_size)

		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return artifacts, fmt.Errorf("error creating http request - err: %v", err)
		}

		if len(HARBOR_USERNAME) > 0 {
			req.SetBasicAuth(HARBOR_USERNAME, HARBOR_PASSWORD)
		}

		rsp, err := client.Do(req)
		if err != nil {
			return artifacts, fmt.Errorf("error sending http request - err: %v", err)
		}
		defer rsp.Body.Close()

		data, err := io.ReadAll(rsp.Body)
		if err != nil {
			return artifacts, fmt.Errorf("error reading response - err: %v", err)
		}

		var arts []HarborArtifact
		if err := json.Unmarshal(data, &arts); err != nil {
			return artifacts, fmt.Errorf("error during json unmarshal - err: %v", err)
		}

		if len(arts) == 0 {
			break
		}

		artifacts = append(artifacts, arts...)
		page++
	}

	return artifacts, nil
}

func (h *HarborClient) ListArtifacts() error {
	var Projects []string

	if len(HARBOR_PROJECT) > 0 {
		Projects = append(Projects, HARBOR_PROJECT)
	} else {
		projects, err := h.GetProjectList()
		if err != nil {
			return err
		}

		for _, proj := range projects {
			Projects = append(Projects, proj.Name)
		}
	}

	for _, proj := range Projects {
		var Repositories []string

		if len(HARBOR_REPOSITORY) > 0 {
			Repositories = append(Repositories, HARBOR_REPOSITORY)
		} else {
			repositories, err := h.GetRepositoryList(proj)
			if err != nil {
				return err
			}

			for _, repo := range repositories {
				index := strings.Index(repo.Name, "/") + 1
				Repositories = append(Repositories, repo.Name[index:])
			}
		}

		for _, repo := range Repositories {
			artifacts, err := h.GetArtifactList(proj, repo)
			if err != nil {
				log.Errorf("project: %s - repository: %s - %v", proj, repo, err)
				continue
			}

			log.Printf("[Harbor] Project: %s - Repository: %s - Total of artifacts: %d", proj, repo, len(artifacts))

			if len(artifacts) > 0 {
				header := table.Row{"ID", "TAG NAME", "DIGEST", "TYPE", "SIZE", "SIGNED"}
				rows := []table.Row{}

				for _, artifact := range artifacts {
					for _, tag := range artifact.Tags {
						rows = append(rows, table.Row{
							artifact.ID,
							tag.Name,
							artifact.Digest,
							artifact.Type,
							artifact.Size,
							tag.Signed,
						})
					}
				}

				CreateTable(header, rows)
				fmt.Println()
			}
		}
	}

	return nil
}

func (h *HarborClient) GetRepositoryList(project string) ([]HarborRepository, error) {
	var repositories []HarborRepository

	page := 1
	page_size := 100

	client, err := NewHttpClient()
	if err != nil {
		return repositories, fmt.Errorf("error creating http client - err: %v", err)
	}

	for {
		endpoint := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories?page=%d&page_size=%d", HARBOR_SERVER, project, page, page_size)

		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return repositories, fmt.Errorf("error creating http request - err: %v", err)
		}

		if len(HARBOR_USERNAME) > 0 {
			req.SetBasicAuth(HARBOR_USERNAME, HARBOR_PASSWORD)
		}

		rsp, err := client.Do(req)
		if err != nil {
			return repositories, fmt.Errorf("error sending http request - err: %v", err)
		}
		defer rsp.Body.Close()

		data, err := io.ReadAll(rsp.Body)
		if err != nil {
			return repositories, fmt.Errorf("error reading response - err: %v", err)
		}

		var repos []HarborRepository
		if err := json.Unmarshal(data, &repos); err != nil {
			return repositories, fmt.Errorf("error during json unmarshal - err: %v", err)
		}

		if len(repos) == 0 {
			break
		}

		repositories = append(repositories, repos...)
		page++
	}

	return repositories, nil
}

func (h *HarborClient) GetProjectList() ([]HarborProject, error) {
	var projects []HarborProject

	page := 1
	page_size := 100

	client, err := NewHttpClient()
	if err != nil {
		return projects, fmt.Errorf("error creating http client - err: %v", err)
	}

	for {
		endpoint := fmt.Sprintf("%s/api/v2.0/projects?page=%d&page_size=%d", HARBOR_SERVER, page, page_size)

		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return projects, fmt.Errorf("error creating http request - err: %v", err)
		}

		if len(HARBOR_USERNAME) > 0 {
			req.SetBasicAuth(HARBOR_USERNAME, HARBOR_PASSWORD)
		}

		rsp, err := client.Do(req)
		if err != nil {
			return projects, fmt.Errorf("error sending http request - err: %v", err)
		}
		defer rsp.Body.Close()

		data, err := io.ReadAll(rsp.Body)
		if err != nil {
			return projects, fmt.Errorf("error reading response - err: %v", err)
		}

		var projs []HarborProject
		if err := json.Unmarshal(data, &projs); err != nil {
			return projects, fmt.Errorf("error during json unmarshal - err: %v", err)
		}

		if len(projs) == 0 {
			break
		}

		projects = append(projects, projs...)
		page++
	}

	return projects, nil
}

func (h *HarborClient) ListProjects() error {
	log.Printf("[Harbor] Listing Projects - Server: %s", HARBOR_SERVER)

	projects, err := h.GetProjectList()
	if err != nil {
		return err
	}

	log.Printf("[Harbor] Total of projects: %d \n", len(projects))

	if len(projects) > 0 {
		header := table.Row{"ID", "NAME", "REPO COUNT", "VISIBILITY"}
		rows := []table.Row{}

		for _, p := range projects {
			visibility := "PRIVATE"
			if strings.Compare(p.Metadata.Public, visibility) != 0 {
				visibility = "PUBLIC"
			}

			rows = append(rows, table.Row{
				p.ProjectID,
				p.Name,
				p.RepoCount,
				visibility,
			})
		}

		CreateTable(header, rows)
	}

	return nil
}

func (h *HarborClient) ListRepositories() error {
	log.Printf("[Harbor] Listing Repositories - Server: %s", HARBOR_SERVER)

	var Projects []string

	if len(HARBOR_PROJECT) > 0 {
		Projects = append(Projects, HARBOR_PROJECT)
	} else {
		projects, err := h.GetProjectList()
		if err != nil {
			return err
		}

		for _, proj := range projects {
			Projects = append(Projects, proj.Name)
		}
	}

	for _, proj := range Projects {
		log.Infof("[Harbor] Listing Repositories - Project: %s", proj)

		repositories, err := h.GetRepositoryList(proj)
		if err != nil {
			log.Error(err)
			continue
		}

		if len(repositories) > 0 {
			header := table.Row{"ID", "NAME", "CREATION TIME", "ARTIFACT COUNT"}
			rows := []table.Row{}

			log.Printf("[Harbor] Listing repositories - Project: %s", proj)

			for _, repo := range repositories {
				name := strings.Replace(repo.Name, fmt.Sprintf("%s/", proj), "", 1)

				rows = append(rows, table.Row{
					repo.ID,
					name,
					repo.CreationTime,
					repo.ArtifactCount,
				})
			}

			CreateTable(header, rows)
		}

		fmt.Println()
	}

	return nil
}

func (h *HarborClient) GetServiceToken(project string, repository string) (HarborServiceToken, error) {
	var st HarborServiceToken

	scope := fmt.Sprintf("repository:%s/%s:pull", project, repository)

	endpoint := fmt.Sprintf("%s/service/token?scope=%s&service=harbor-registry", HARBOR_SERVER, scope)

	client, err := NewHttpClient()
	if err != nil {
		return st, fmt.Errorf("error creating http client - err: %v", err)
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return st, fmt.Errorf("error creating http request - err: %v", err)
	}

	rsp, err := client.Do(req)
	if err != nil {
		return st, fmt.Errorf("error sending http request - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return st, fmt.Errorf("error reading response - err: %v", err)
	}

	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("error during json unmarshal - err: %v", err)
	}

	return st, nil
}

func (h *HarborClient) GetHarborManifest(project string, repository string, tag string, token string) (HarborManifest, error) {
	var manifest HarborManifest

	url := fmt.Sprintf("%s/v2/%s/%s/manifests/%s", strings.TrimSuffix(HARBOR_SERVER, "/"), project, repository, tag)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return manifest, fmt.Errorf("error in new request - err: %v", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	client, err := NewHttpClient()
	if err != nil {
		return manifest, err
	}

	rsp, err := client.Do(req)
	if err != nil {
		return manifest, fmt.Errorf("error sending request - err: %v", err)
	}
	defer rsp.Body.Close()

	err = json.NewDecoder(rsp.Body).Decode(&manifest)
	if err != nil {
		return manifest, fmt.Errorf("error in JSON decoding - err: %v", err)
	}

	return manifest, nil
}

func (h *HarborClient) DownloadImages() error {
	var Projects []string

	if len(HARBOR_PROJECT) > 0 {
		Projects = append(Projects, HARBOR_PROJECT)
	} else {
		projects, err := h.GetProjectList()
		if err != nil {
			return err
		}

		for _, proj := range projects {
			Projects = append(Projects, proj.Name)
		}
	}

	for _, proj := range Projects {
		var Repositories []string

		if len(HARBOR_REPOSITORY) > 0 {
			Repositories = append(Repositories, HARBOR_REPOSITORY)
		} else {
			repositories, err := h.GetRepositoryList(proj)
			if err != nil {
				return err
			}

			for _, repo := range repositories {
				index := strings.Index(repo.Name, "/") + 1
				Repositories = append(Repositories, repo.Name[index:])
			}
		}

		for _, repo := range Repositories {
			st, err := h.GetServiceToken(proj, repo)
			if err != nil {
				log.Error(err)
				continue
			}

			REGISTRY_SERVER = HARBOR_SERVER
			REGISTRY_IMAGES = HARBOR_IMAGES
			REGISTRY_TOKEN = st.Token

			img := fmt.Sprintf("%s/%s", proj, repo)

			tags := []string{}
			if len(HARBOR_TAG) > 0 {
				tags = append(tags, HARBOR_TAG)
			} else {
				tags, err = GetImageTags(img)
				if err != nil {
					log.Error(err)
					continue
				}
			}

			for _, tag := range tags {
				manifest, err := HC.GetHarborManifest(proj, repo, tag, st.Token)
				if err != nil {
					log.Error(err)
					continue
				}

				for _, layer := range manifest.Layers {
					if err := DownloadBlob(img, layer.Digest, tag); err != nil {
						log.Error(err)
					}
				}
			}
		}
	}

	return nil
}

var harborListProjects = &cobra.Command{
	Use:    "list-projects",
	Short:  "List Projects",
	Long:   `List Projects`,
	PreRun: NewHarborClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := HC.ListProjects(); err != nil {
			log.Fatal(err)
		}
	},
}

var harborListRepositories = &cobra.Command{
	Use:    "list-repositories",
	Short:  "List Repositories",
	Long:   `List Repositories`,
	PreRun: NewHarborClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := HC.ListRepositories(); err != nil {
			log.Fatal(err)
		}
	},
}

var harborListArtifacts = &cobra.Command{
	Use:    "list-artifacts",
	Short:  "List Artifacts",
	Long:   `List Artifacts`,
	PreRun: NewHarborClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := HC.ListArtifacts(); err != nil {
			log.Fatal(err)
		}
	},
}

var harborListBuildHistory = &cobra.Command{
	Use:    "list-build-history",
	Short:  "List Build History",
	Long:   `List Build History`,
	PreRun: NewHarborClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := HC.ListBuildCommands(); err != nil {
			log.Fatal(err)
		}
	},
}

var harborListSystemInfo = &cobra.Command{
	Use:    "system-info",
	Short:  "List System Info",
	Long:   `List System Info`,
	PreRun: NewHarborClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := HC.ListSystemInfo(); err != nil {
			log.Fatal(err)
		}
	},
}

var harborBackdoorAccount = &cobra.Command{
	Use:    "backdoor-account",
	Short:  "Create Backdoor Account (requires privs)",
	Long:   `Create Backdoor Account (requires privs)`,
	PreRun: NewHarborClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := HC.CreateAccount(); err != nil {
			log.Fatal(err)
		}
	},
}

var harborListImages = &cobra.Command{
	Use:    "list-images",
	Short:  "List Container Images",
	Long:   `List Container Images`,
	PreRun: NewHarborClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := HC.ListImages(); err != nil {
			log.Fatal(err)
		}
	},
}

var harborDownloadImages = &cobra.Command{
	Use:    "download-images",
	Short:  "Download Container Images",
	Long:   `Download Container Images`,
	PreRun: NewHarborClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := HC.DownloadImages(); err != nil {
			log.Fatal(err)
		}
	},
}

var harborCmd = &cobra.Command{
	Use:   "harbor",
	Short: "Interact with Harbor Server",
	Long:  `Options for Harbor Interaction`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

func init() {
	rootCmd.AddCommand(harborCmd)

	harborCmd.AddCommand(harborListProjects)
	harborCmd.AddCommand(harborListRepositories)
	harborCmd.AddCommand(harborListArtifacts)
	harborCmd.AddCommand(harborListBuildHistory)
	harborCmd.AddCommand(harborListSystemInfo)
	harborCmd.AddCommand(harborBackdoorAccount)
	harborCmd.AddCommand(harborListImages)
	harborCmd.AddCommand(harborDownloadImages)

	harborCmd.PersistentFlags().StringVarP(&HARBOR_SERVER, "server", "s", "", "Server Address")
	harborCmd.PersistentFlags().StringVarP(&HARBOR_USERNAME, "user", "u", "", "Username")
	harborCmd.PersistentFlags().StringVarP(&HARBOR_PASSWORD, "pass", "p", "", "Password")

	harborListRepositories.Flags().StringVarP(&HARBOR_PROJECT, "name", "n", "", "Project Name")

	harborListArtifacts.Flags().StringVarP(&HARBOR_PROJECT, "name", "n", "", "Project Name")
	harborListArtifacts.Flags().StringVarP(&HARBOR_REPOSITORY, "repository", "r", "", "Repository Name")

	harborListBuildHistory.Flags().StringVarP(&HARBOR_PROJECT, "name", "n", "", "Project Name")
	harborListBuildHistory.Flags().StringVarP(&HARBOR_REPOSITORY, "repository", "r", "", "Repository Name")

	harborListImages.Flags().StringVarP(&HARBOR_PROJECT, "name", "n", "", "Project Name")
	harborListImages.Flags().StringVarP(&HARBOR_REPOSITORY, "repository", "r", "", "Repository Name")

	harborDownloadImages.Flags().StringVarP(&HARBOR_PROJECT, "name", "n", "", "Project Name")
	harborDownloadImages.Flags().StringVarP(&HARBOR_REPOSITORY, "repository", "r", "", "Repository Name")
	harborDownloadImages.Flags().StringVarP(&HARBOR_TAG, "tag", "t", "", "Image Tag")

	var err error

	if HARBOR_PROJECTS, err = GetConfigParam("harbor.projects"); err != nil {
		log.Fatal(err)
	}

	if HARBOR_IMAGES, err = GetConfigParam("harbor.images"); err != nil {
		log.Fatal(err)
	}
}
