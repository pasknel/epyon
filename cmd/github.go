package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"

	"github.com/google/go-github/v56/github"
	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var (
	GC                *GithubClient
	GITHUB_TOKEN      string
	GITHUB_ORG        string
	GITHUB_PROJECTS   string
	GITHUB_WORKERS    int
	GITHUB_LATEST_RUN bool
	GITHUB_WORKFLOWS  string
	GITHUB_PAGE_SIZE  int
)

type GithubClient struct {
	Client *github.Client
	Ctx    context.Context
}

func NewGithubClient(cmd *cobra.Command, args []string) {
	custom_client, err := NewHttpClient()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, custom_client)

	gc := GithubClient{
		Ctx: ctx,
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: GITHUB_TOKEN},
	)

	http_client := oauth2.NewClient(gc.Ctx, ts)

	gc.Client = github.NewClient(http_client)

	GC = &gc
}

func (g *GithubClient) ListOrgRepos(org string) error {
	log.Infof("[Github] Listing repositories from org: %s", GITHUB_ORG)

	opt := &github.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: github.ListOptions{PerPage: GITHUB_PAGE_SIZE},
	}

	header := table.Row{"ORG", "ID", "NAME", "TYPE"}
	results := []table.Row{}

	for {
		repos, rsp, err := g.Client.Repositories.ListByOrg(g.Ctx, org, opt)
		if err != nil {
			return fmt.Errorf("error listing org repositories - err: %v", err)
		}

		for _, r := range repos {
			repoType := "Public"
			if r.GetPrivate() {
				repoType = "Private"
			}

			if VERBOSE {
				log.WithFields(log.Fields{
					"org":       org,
					"id":        r.GetID(),
					"name":      r.GetName(),
					"clone_url": r.GetCloneURL(),
					"type":      repoType,
				}).Info("Github Project")
			}

			results = append(results, table.Row{
				org,
				r.GetID(),
				r.GetName(),
				repoType,
			})
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GithubClient) ListRepos() error {
	log.Info("[Github] Listing repositories")

	opt := github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: GITHUB_PAGE_SIZE},
	}

	header := table.Row{"ID", "NAME", "TYPE"}
	results := []table.Row{}

	for {
		repos, rsp, err := g.Client.Repositories.List(g.Ctx, "", &opt)
		if err != nil {
			return fmt.Errorf("error listing repositories - err: %v", err)
		}

		for _, r := range repos {
			repoType := "Public"
			if r.GetPrivate() {
				repoType = "Private"
			}

			if VERBOSE {
				log.WithFields(log.Fields{
					"id":        r.GetID(),
					"name":      r.GetName(),
					"clone_url": r.GetCloneURL(),
					"type":      repoType,
				}).Info("Github Project")
			}

			results = append(results, table.Row{
				r.GetID(),
				r.GetName(),
				repoType,
			})
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GithubClient) ListOrgMembers(org string) error {
	log.Infof("[Github] Listing members from org: %s", GITHUB_ORG)

	opt := &github.ListMembersOptions{
		ListOptions: github.ListOptions{PerPage: GITHUB_PAGE_SIZE},
	}

	header := table.Row{"LOGIN", "URL"}
	results := []table.Row{}

	for {
		members, rsp, err := g.Client.Organizations.ListMembers(g.Ctx, org, opt)
		if err != nil {
			return fmt.Errorf("error listing org members - err: %v", err)
		}

		for _, m := range members {
			if VERBOSE {
				log.WithFields(log.Fields{
					"login": m.GetLogin(),
					"url":   m.GetURL(),
					"email": m.GetEmail(),
				}).Info("Organization Member")
			}

			results = append(results, table.Row{
				m.GetLogin(),
				m.GetURL(),
			})
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GithubClient) ListWorkflows() error {
	log.Info("[Github] Listing workflows")

	opt := github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: GITHUB_PAGE_SIZE},
	}

	header := table.Row{"PROJECT", "OWNER", "WORKFLOW"}
	results := []table.Row{}

	for {
		repos, rsp, err := g.Client.Repositories.List(g.Ctx, "", &opt)
		if err != nil {
			return fmt.Errorf("error listing repositories - err: %v", err)
		}

		for _, r := range repos {
			opt := &github.ListOptions{}

			workflows, _, err := g.Client.Actions.ListWorkflows(g.Ctx, *r.Owner.Login, *r.Name, opt)
			if err != nil {
				return fmt.Errorf("error listing workflows - err: %v", err)
			}

			for _, w := range workflows.Workflows {
				if VERBOSE {
					log.WithFields(log.Fields{
						"project":  r.GetName(),
						"owner":    r.GetOwner().GetLogin(),
						"workflow": w.GetName(),
					}).Info("Github Actions (Workflows)")
				}

				results = append(results, table.Row{
					r.GetName(),
					r.GetOwner().GetLogin(),
					w.GetName(),
				})
			}
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GithubClient) ListOrgWorkflows(org string) error {
	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: GITHUB_PAGE_SIZE},
		Type:        "public",
	}

	header := table.Row{"PROJECT", "OWNER", "WORKFLOW"}
	results := []table.Row{}

	for {
		repos, rsp, err := g.Client.Repositories.ListByOrg(g.Ctx, org, opt)
		if err != nil {
			log.Fatal(err)
		}

		for _, r := range repos {
			opt := &github.ListOptions{}

			workflows, _, err := g.Client.Actions.ListWorkflows(g.Ctx, *r.Owner.Login, *r.Name, opt)
			if err != nil {
				log.Fatal(err)
			}

			for _, w := range workflows.Workflows {
				if VERBOSE {
					log.WithFields(log.Fields{
						"project":  r.GetName(),
						"owner":    r.GetOwner().GetLogin(),
						"workflow": w.GetName(),
					}).Info("Github Actions (Workflows)")
				}

				results = append(results, table.Row{
					r.GetName(),
					r.GetOwner().GetLogin(),
					w.GetName(),
				})
			}
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GithubClient) DownloadProjects() error {
	log.Info("[Github] Downloading projects")

	var wg sync.WaitGroup
	wg.Add(GITHUB_WORKERS)

	repos_chan := make(chan *github.Repository)

	for i := 0; i < GITHUB_WORKERS; i++ {
		go g.DownloadWorker(repos_chan, &wg)
	}

	opt := github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: GITHUB_PAGE_SIZE},
	}

	for {
		repos, rsp, err := g.Client.Repositories.List(g.Ctx, "", &opt)
		if err != nil {
			log.Fatal(err)
		}

		for _, r := range repos {
			repos_chan <- r
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	close(repos_chan)
	wg.Wait()

	return nil
}

func (g *GithubClient) DownloadOrgProjects(org string) error {
	log.Info("[Github] Downloading organization projects")

	var wg sync.WaitGroup
	wg.Add(GITHUB_WORKERS)

	repos_chan := make(chan *github.Repository)

	for i := 0; i < GITHUB_WORKERS; i++ {
		go g.DownloadWorker(repos_chan, &wg)
	}

	opt := &github.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: github.ListOptions{PerPage: GITHUB_PAGE_SIZE},
	}

	for {
		repos, rsp, err := g.Client.Repositories.ListByOrg(g.Ctx, org, opt)
		if err != nil {
			return fmt.Errorf("error listing org repositories - err: %v", err)
		}

		for _, r := range repos {
			repos_chan <- r
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	close(repos_chan)
	wg.Wait()

	return nil
}

func (g *GithubClient) DownloadWorker(repos chan *github.Repository, wg *sync.WaitGroup) {
	defer wg.Done()

	for r := range repos {
		outdir := fmt.Sprintf("%s/%d/", GITHUB_PROJECTS, r.GetID())
		os.MkdirAll(outdir, os.ModePerm)

		if err := DefaultGitCloneWithToken(r.GetCloneURL(), GITHUB_TOKEN, outdir, "github"); err != nil {
			log.Error(err)
			continue
		}

		log.Printf("[Github] Download finished - repository: %s", r.GetName())
	}
}

func (g *GithubClient) ListUserOrgs() error {
	log.Info("[Github] Listing organizations")

	opt := github.ListOptions{PerPage: GITHUB_PAGE_SIZE}

	header := table.Row{"ID", "NAME", "DESCRIPTION"}
	results := []table.Row{}

	for {
		orgs, rsp, err := g.Client.Organizations.List(g.Ctx, "", &opt)
		if err != nil {
			return fmt.Errorf("error listing organizations - err: %v", err)
		}

		for _, org := range orgs {
			if VERBOSE {
				log.WithFields(log.Fields{
					"name": org.GetLogin(),
					"id":   org.GetID(),
				}).Info("organization")
			}

			results = append(results, table.Row{
				org.GetID(),
				org.GetLogin(),
				org.GetDescription(),
			})
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GithubClient) GetRunsLogs() error {
	opt := github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: GITHUB_PAGE_SIZE},
	}

	for {
		repos, rsp, err := g.Client.Repositories.List(g.Ctx, "", &opt)
		if err != nil {
			return fmt.Errorf("error listing repositories - err: %v", err)
		}

		for _, r := range repos {
			opt := &github.ListOptions{}

			workflows, _, err := g.Client.Actions.ListWorkflows(g.Ctx, *r.Owner.Login, *r.Name, opt)
			if err != nil {
				log.Error("error listing workflows - err: %v", err)
				continue
			}

			for _, w := range workflows.Workflows {
				opt := &github.ListWorkflowRunsOptions{}

				runs, _, err := g.Client.Actions.ListWorkflowRunsByID(g.Ctx, *r.Owner.Login, *r.Name, *w.ID, opt)
				if err != nil {
					log.Error("error listing workflow runs - err: %v", err)
				}

				if len(runs.WorkflowRuns) > 0 {
					runsDir := fmt.Sprintf("%s/%s/%s/runs", GITHUB_WORKFLOWS, r.GetName(), w.GetName())
					os.MkdirAll(runsDir, os.ModePerm)

					for _, wr := range runs.WorkflowRuns {
						http_client := g.Client.Client()

						req, err := http.NewRequest("GET", wr.GetLogsURL(), nil)
						if err != nil {
							log.Errorf("error creating GET request - err: %v", err)
							continue
						}

						rsp, err := http_client.Do(req)
						if err != nil {
							log.Errorf("error sending GET request - err: %v", err)
							continue
						}
						defer rsp.Body.Close()

						data, err := ioutil.ReadAll(rsp.Body)
						if err != nil {
							log.Errorf("error reading HTTP response - err: %v", err)
							continue
						}

						logName := fmt.Sprintf("%s/%d.zip", runsDir, r.GetID())

						if err = ioutil.WriteFile(logName, data, 0644); err != nil {
							log.Errorf("error saving log file - err: %v", err)
						}

						log.Infof("[Github] Download finished - Log file: %s", logName)

						if GITHUB_LATEST_RUN {
							break
						}
					}
				}
			}
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}
	return nil
}

func (g *GithubClient) GetArtifacts() error {
	opt := github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: GITHUB_PAGE_SIZE},
	}

	for {
		repos, rsp, err := g.Client.Repositories.List(g.Ctx, "", &opt)
		if err != nil {
			return fmt.Errorf("error listing repositories - err: %v", err)
		}

		for _, r := range repos {
			opt := &github.ListOptions{}

			workflows, _, err := g.Client.Actions.ListWorkflows(g.Ctx, *r.Owner.Login, *r.Name, opt)
			if err != nil {
				log.Error("error listing workflows - err: %v", err)
				continue
			}

			for _, w := range workflows.Workflows {
				opt := &github.ListWorkflowRunsOptions{}

				runs, _, err := g.Client.Actions.ListWorkflowRunsByID(g.Ctx, *r.Owner.Login, *r.Name, *w.ID, opt)
				if err != nil {
					log.Error("error listing workflow runs - err: %v", err)
				}

				artifactsDir := fmt.Sprintf("%s/%s/%s/artifacts", GITHUB_WORKFLOWS, r.GetName(), w.GetName())
				os.MkdirAll(artifactsDir, os.ModePerm)

				for _, wr := range runs.WorkflowRuns {
					http_client := g.Client.Client()

					req, err := http.NewRequest("GET", wr.GetArtifactsURL(), nil)
					if err != nil {
						log.Errorf("error creating GET request - err: %v", err)
						continue
					}

					rsp, err := http_client.Do(req)
					if err != nil {
						log.Errorf("error sending GET request - err: %v", err)
						continue
					}
					defer rsp.Body.Close()

					data, err := ioutil.ReadAll(rsp.Body)
					if err != nil {
						log.Errorf("error reading HTTP response - err: %v", err)
						continue
					}

					artifactName := fmt.Sprintf("%s/%d.zip", artifactsDir, r.GetID())

					if err = ioutil.WriteFile(artifactName, data, 0644); err != nil {
						log.Errorf("error saving artifact file - err: %v", err)
					}

					log.Infof("[Github] Download finished - Artifact file: %s", artifactName)

					if GITHUB_LATEST_RUN {
						break
					}
				}
			}
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	return nil
}

func (g *GithubClient) ListUserTeams() error {
	log.Println("[Github] Listing user teams")

	opt := github.ListOptions{PerPage: GITHUB_PAGE_SIZE}

	header := table.Row{"NAME", "MEMBERS COUNT", "REPOS COUNT"}
	results := []table.Row{}

	for {
		teams, rsp, err := g.Client.Teams.ListUserTeams(g.Ctx, &opt)
		if err != nil {
			return fmt.Errorf("error listing teams - err: %v", err)
		}

		for _, t := range teams {
			if VERBOSE {
				log.WithFields(log.Fields{
					"name": t.GetName(),
				}).Info("team found")
			}

			results = append(results, table.Row{
				t.GetName(),
				*t.MembersCount,
				*t.ReposCount,
			})
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	CreateTable(header, results)

	return nil
}

func (g *GithubClient) Whoami() error {
	log.Println("[Github] Getting information about the current user")

	user, _, err := g.Client.Users.Get(g.Ctx, "")
	if err != nil {
		return fmt.Errorf("error getting user information - err: %v", err)
	}

	header := table.Row{"LOGIN", "NAME", "EMAIL", "2FA", "BIO"}
	results := []table.Row{}

	results = append(results, table.Row{
		user.GetLogin(),
		user.GetName(),
		user.GetEmail(),
		user.GetTwoFactorAuthentication(),
		user.GetBio(),
	})

	CreateTable(header, results)

	return nil
}

func (g *GithubClient) ListOrgVars() error {
	log.Println("[Github] Listing Organization Variables")

	opt := &github.ListOptions{
		PerPage: 10,
	}

	header := table.Row{"NAME", "VALUE", "CREATED AT"}
	results := []table.Row{}

	for {
		variables, rsp, err := g.Client.Actions.ListOrgVariables(GC.Ctx, GITHUB_ORG, opt)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range variables.Variables {
			results = append(results, table.Row{
				v.Name,
				v.Value,
				v.CreatedAt,
			})
		}

		if rsp.NextPage == 0 {
			break
		}

		opt.Page = rsp.NextPage
	}

	if len(results) > 0 {
		CreateTable(header, results)
	}

	return nil
}

func (g *GithubClient) ListOrgSecrets() error {
	log.Println("[Github] Listing Organization Secrets")

	opt := &github.ListOptions{
		PerPage: 10,
	}

	header := table.Row{"NAME", "CREATED AT", "VISIBILITY"}
	results := []table.Row{}

	for {
		secrets, rsp, err := g.Client.Actions.ListOrgSecrets(GC.Ctx, GITHUB_ORG, opt)
		if err != nil {
			log.Fatal(err)
		}

		for _, secret := range secrets.Secrets {
			results = append(results, table.Row{
				secret.Name,
				secret.CreatedAt,
				secret.Visibility,
			})
		}

		if rsp.NextPage == 0 {
			break
		}

		opt.Page = rsp.NextPage
	}

	if len(results) > 0 {
		CreateTable(header, results)
	}

	return nil
}

func (g *GithubClient) ListRepoSecrets() error {
	log.Println("[Github] Listing Repositories Secrets")

	user, _, err := g.Client.Users.Get(g.Ctx, "")
	if err != nil {
		return fmt.Errorf("error getting user information - err: %v", err)
	}

	opt := github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: GITHUB_PAGE_SIZE},
	}

	for {
		repos, rsp, err := g.Client.Repositories.List(g.Ctx, "", &opt)
		if err != nil {
			log.Fatal(err)
		}

		for _, r := range repos {
			secrets, _, err := g.Client.Actions.ListRepoSecrets(g.Ctx, user.GetLogin(), r.GetName(), &github.ListOptions{})
			if err != nil {
				log.Errorf("error listing repository secrets - err: %v", err)
				continue
			}

			header := table.Row{"REPOSITORY NAME", "SECRET NAME", "CREATED AT"}
			results := []table.Row{}

			for _, secret := range secrets.Secrets {
				results = append(results, table.Row{
					r.GetName(),
					secret.Name,
					secret.CreatedAt,
				})
			}

			if len(results) > 0 {
				CreateTable(header, results)
			}
		}

		if rsp.NextPage == 0 {
			break
		}
		opt.Page = rsp.NextPage
	}

	return nil
}

var githubListOrgSecrets = &cobra.Command{
	Use:    "list-org-secrets",
	Short:  "List Organization Secrets (requires admin privs)",
	Long:   `List Organization Secrets (requires admin privs)`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.ListOrgSecrets()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubListOrgVars = &cobra.Command{
	Use:    "list-org-vars",
	Short:  "List Organization Variables (requires admin privs)",
	Long:   `List Organization Variables (requires admin privs)`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.ListOrgVars()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubListRepoSecrets = &cobra.Command{
	Use:    "list-repo-secrets",
	Short:  "List Repositories Secrets",
	Long:   `List Repositories Secrets`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.ListRepoSecrets()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubWhoami = &cobra.Command{
	Use:    "whoami",
	Short:  "Get information about the current user",
	Long:   `Get information about the current user`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.Whoami()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubListUserTeams = &cobra.Command{
	Use:    "list-user-teams",
	Short:  "List User Teams",
	Long:   `List User Teams`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.ListUserTeams()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubListOrgRepos = &cobra.Command{
	Use:    "list-org-repos",
	Short:  "List Organization Repositories",
	Long:   `List Organization Repositories`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.ListOrgRepos(GITHUB_ORG)
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubListRepos = &cobra.Command{
	Use:    "list-repos",
	Short:  "List Repositories",
	Long:   `List Repositories`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.ListRepos()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubListOrgMembers = &cobra.Command{
	Use:    "list-org-members",
	Short:  "List Organization Members",
	Long:   `List Organization Members`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.ListOrgMembers(GITHUB_ORG)
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubListWorkflows = &cobra.Command{
	Use:    "list-workflows",
	Short:  "List Workflows",
	Long:   `List Workflows`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.ListWorkflows()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubListOrgWorkflows = &cobra.Command{
	Use:    "list-org-workflows",
	Short:  "List Organization Workflows",
	Long:   `List Organization Workflows`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.ListOrgWorkflows(GITHUB_ORG)
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubDownloadProjects = &cobra.Command{
	Use:    "download-projects",
	Short:  "Download Projects",
	Long:   `Download Projects`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.DownloadProjects()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubListUserOrgs = &cobra.Command{
	Use:    "list-orgs",
	Short:  "List organizations the user is a member of",
	Long:   `List organizations the user is a member of`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.ListUserOrgs()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubGetRunsLogs = &cobra.Command{
	Use:    "get-logs",
	Short:  "Get logs from workflows runs",
	Long:   `Get logs from workflows runs`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.GetRunsLogs()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubGetArtifacts = &cobra.Command{
	Use:    "get-artifacts",
	Short:  "Get artifacts from workflows runs",
	Long:   `Get artifacts from workflows runs`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.GetArtifacts()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubDownloadOrgProjects = &cobra.Command{
	Use:    "download-org-projects",
	Short:  "Download Organization Projects",
	Long:   `Download Organization Projects`,
	PreRun: NewGithubClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GC.DownloadOrgProjects(GITHUB_ORG)
		if err != nil {
			log.Fatal(err)
		}
	},
}

var githubCmd = &cobra.Command{
	Use:   "github",
	Short: "Interact with Github (Enterprise and Actions)",
	Long:  "Options for Github",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

func init() {
	rootCmd.AddCommand(githubCmd)

	githubCmd.AddCommand(githubListRepos)
	githubCmd.AddCommand(githubListOrgRepos)
	githubCmd.AddCommand(githubListOrgMembers)
	githubCmd.AddCommand(githubListWorkflows)
	githubCmd.AddCommand(githubListOrgWorkflows)
	githubCmd.AddCommand(githubDownloadProjects)
	githubCmd.AddCommand(githubListUserOrgs)
	githubCmd.AddCommand(githubGetRunsLogs)
	githubCmd.AddCommand(githubGetArtifacts)
	githubCmd.AddCommand(githubDownloadOrgProjects)
	githubCmd.AddCommand(githubListUserTeams)
	githubCmd.AddCommand(githubWhoami)
	githubCmd.AddCommand(githubListRepoSecrets)
	githubCmd.AddCommand(githubListOrgSecrets)
	githubCmd.AddCommand(githubListOrgVars)

	githubCmd.PersistentFlags().StringVarP(&GITHUB_TOKEN, "token", "t", "", "Access Token")
	githubListOrgRepos.PersistentFlags().StringVarP(&GITHUB_ORG, "org", "o", "", "Organization Name")
	githubListOrgMembers.PersistentFlags().StringVarP(&GITHUB_ORG, "org", "o", "", "Organization Name")
	githubListOrgWorkflows.PersistentFlags().StringVarP(&GITHUB_ORG, "org", "o", "", "Organization Name")
	githubDownloadOrgProjects.PersistentFlags().StringVarP(&GITHUB_ORG, "org", "o", "", "Organization Name")
	githubGetRunsLogs.PersistentFlags().BoolVarP(&GITHUB_LATEST_RUN, "latest", "l", false, "Get only latest run from each workflow")
	githubListOrgSecrets.PersistentFlags().StringVarP(&GITHUB_ORG, "org", "o", "", "Organization Name")
	githubListOrgVars.PersistentFlags().StringVarP(&GITHUB_ORG, "org", "o", "", "Organization Name")

	var err error

	if GITHUB_PROJECTS, err = GetConfigParam("github.projects"); err != nil {
		log.Fatal(err)
	}

	if GITHUB_WORKFLOWS, err = GetConfigParam("github.workflows"); err != nil {
		log.Fatal(err)
	}

	if GITHUB_WORKERS, err = GetConfigParamInt("github.workers"); err != nil {
		log.Fatal(err)
	}

	if GITHUB_PAGE_SIZE, err = GetConfigParamInt("github.pagesize"); err != nil {
		log.Fatal(err)
	}
}
