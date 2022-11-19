package cmd

import (
	"fmt"
	"os"
	"sync"

	"code.gitea.io/sdk/gitea"
	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	GITEA_SERVER   string
	GITEA_USERNAME string
	GITEA_PASSWORD string
	GITEA_TOKEN    string
	GITEA_CLIENT   GiteaClient
	GITEA_PROJECTS string
)

type GiteaClient struct {
	Client *gitea.Client
}

func NewGiteaClient(cmd *cobra.Command, args []string) {
	var opt gitea.ClientOption

	if len(GITEA_TOKEN) > 0 {
		opt = gitea.SetToken(GITEA_TOKEN)
	} else {
		opt = gitea.SetBasicAuth(GITEA_USERNAME, GITEA_PASSWORD)
	}

	client, err := gitea.NewClient(GITEA_SERVER, opt)
	if err != nil {
		log.Fatal(err)
	}

	GITEA_CLIENT.Client = client
}

func (g *GiteaClient) GetUserInfo() error {
	log.Println("[Gitea] Listing user info")

	user, _, err := GITEA_CLIENT.Client.GetMyUserInfo()
	if err != nil {
		return fmt.Errorf("error getting user info - err: %v", err)
	}

	rows := []table.Row{}
	rows = append(rows, table.Row{
		user.UserName,
		user.Email,
		user.IsActive,
		user.IsAdmin,
	})

	header := table.Row{"USERNAME", "EMAIL", "IS ACTIVE", "IS ADMIN"}

	CreateTable(header, rows)

	return nil
}

func (g *GiteaClient) ListProjects() error {
	log.Println("[Gitea] Listing projects")

	opt := gitea.SearchRepoOptions{}

	repos, _, err := GITEA_CLIENT.Client.SearchRepos(opt)
	if err != nil {
		return fmt.Errorf("error in SearchRepos - err: %v", repos)
	}

	rows := []table.Row{}
	header := table.Row{"ID", "NAME", "OWNER", "IS PRIVATE", "CLONE URL"}

	for _, repo := range repos {
		rows = append(rows, table.Row{
			repo.ID,
			repo.Name,
			repo.Owner.UserName,
			repo.Private,
			repo.CloneURL,
		})
	}

	CreateTable(header, rows)

	return nil
}

func (g *GiteaClient) DownloadWorker(wg *sync.WaitGroup, repos chan *gitea.Repository) {
	defer wg.Done()

	for r := range repos {
		log.Printf("[Gitea] Downloading - Clone URL: %s", r.CloneURL)
		outdir := fmt.Sprintf("%s/%d", GITEA_PROJECTS, r.ID)
		if len(GITEA_TOKEN) > 0 {
			if err := GitCloneWithToken(r.CloneURL, GITEA_TOKEN, outdir); err != nil {
				log.Error(err)
				continue
			}
		} else {
			if err := GitCloneWithUserPass(r.CloneURL, GITEA_USERNAME, GITEA_PASSWORD, outdir); err != nil {
				log.Error(err)
				continue
			}
		}
		log.Printf("[Gitea] Download finished - Clone URL: %s", r.CloneURL)
	}
}

func (g *GiteaClient) DownloadRepos() error {
	log.Println("[Gitea] Downloading repositories")

	os.MkdirAll(GITEA_PROJECTS, os.ModePerm)

	workers := 10
	repos_chan := make(chan *gitea.Repository)

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go g.DownloadWorker(&wg, repos_chan)
	}

	opt := gitea.SearchRepoOptions{}
	repos, _, err := GITEA_CLIENT.Client.SearchRepos(opt)
	if err != nil {
		return fmt.Errorf("error in SearchRepos - err: %v", repos)
	}

	for _, repo := range repos {
		repos_chan <- repo
	}

	close(repos_chan)
	wg.Wait()

	return nil
}

func (g *GiteaClient) ListUsers() error {
	log.Println("[Gitea] Listing users")

	opt := gitea.SearchUsersOption{}

	users, _, err := GITEA_CLIENT.Client.SearchUsers(opt)
	if err != nil {
		return fmt.Errorf("error in SearchUsers - err: %v", err)
	}

	rows := []table.Row{}
	header := table.Row{"USERNAME", "EMAIL", "IS ACTIVE", "IS ADMIN"}

	for _, user := range users {
		rows = append(rows, table.Row{
			user.UserName,
			user.Email,
			user.IsActive,
			user.IsAdmin,
		})
	}

	CreateTable(header, rows)

	return nil
}

var giteaCmd = &cobra.Command{
	Use:   "gitea",
	Short: "Interact with Gitea server",
	Long:  `Options for Gitea Interaction`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

var giteaListProjectsCmd = &cobra.Command{
	Use:    "list-projects",
	Short:  "List projects",
	Long:   `List projects`,
	PreRun: NewGiteaClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GITEA_CLIENT.ListProjects()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var giteaUserInfoCmd = &cobra.Command{
	Use:    "whoami",
	Short:  "List user info",
	Long:   `List user info`,
	PreRun: NewGiteaClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GITEA_CLIENT.GetUserInfo()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var giteaListUsersCmd = &cobra.Command{
	Use:    "list-users",
	Short:  "List users",
	Long:   `List users`,
	PreRun: NewGiteaClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GITEA_CLIENT.ListUsers()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var giteaDownloadReposCmd = &cobra.Command{
	Use:    "download-repos",
	Short:  "Download repositories",
	Long:   `Download repositories`,
	PreRun: NewGiteaClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := GITEA_CLIENT.DownloadRepos()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(giteaCmd)

	giteaCmd.AddCommand(giteaUserInfoCmd)
	giteaCmd.AddCommand(giteaListProjectsCmd)
	giteaCmd.AddCommand(giteaListUsersCmd)
	giteaCmd.AddCommand(giteaDownloadReposCmd)

	giteaCmd.PersistentFlags().StringVarP(&GITEA_SERVER, "server", "s", "", "Server Address")
	giteaCmd.PersistentFlags().StringVarP(&GITEA_USERNAME, "user", "u", "", "Username")
	giteaCmd.PersistentFlags().StringVarP(&GITEA_PASSWORD, "password", "p", "", "Password")
	giteaCmd.PersistentFlags().StringVarP(&GITEA_TOKEN, "token", "t", "", "Token")

	var err error

	if GITEA_PROJECTS, err = GetConfigParam("gitea.projects"); err != nil {
		log.Fatal(err)
	}
}
