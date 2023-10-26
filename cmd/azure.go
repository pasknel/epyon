package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"

	"github.com/jedib0t/go-pretty/table"
	"github.com/microsoft/azure-devops-go-api/azuredevops"
	"github.com/microsoft/azure-devops-go-api/azuredevops/build"
	"github.com/microsoft/azure-devops-go-api/azuredevops/core"
	"github.com/microsoft/azure-devops-go-api/azuredevops/feed"
	"github.com/microsoft/azure-devops-go-api/azuredevops/git"
	"github.com/microsoft/azure-devops-go-api/azuredevops/pipelines"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

var (
	AZURE_ORG_URL       string
	AZURE_TOKEN         string
	AZURE_PROJECTS_DIR  string
	AZURE_LOGS_DIR      string
	AZURE_ARTIFACTS_DIR string
	AZURE_VARIABLES_DIR string
	AZ                  AzureClient
)

type AzureClient struct {
	c   core.Client
	g   git.Client
	p   pipelines.Client
	f   feed.Client
	b   build.Client
	ctx context.Context
}

func (ac *AzureClient) ListProjects() error {
	log.Info("[Azure DevOps] Listing Projects")

	resp, err := ac.c.GetProjects(ac.ctx, core.GetProjectsArgs{})
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	headers := table.Row{"ID", "NAME"}
	results := []table.Row{}

	for resp != nil {
		for _, project := range (*resp).Value {
			results = append(results, table.Row{*project.Id, *project.Name})
		}

		if resp.ContinuationToken != "" {
			args := core.GetProjectsArgs{
				ContinuationToken: &resp.ContinuationToken,
			}

			resp, err = ac.c.GetProjects(ac.ctx, args)
			if err != nil {
				return fmt.Errorf("err: %v", err)
			}
		} else {
			resp = nil
		}
	}

	CreateTable(headers, results)

	return nil
}

func (ac *AzureClient) DownloadWorker(wg *sync.WaitGroup, repos chan git.GitRepository) {
	defer wg.Done()

	for r := range repos {
		url := *r.RemoteUrl
		i := strings.Index(url, "@") + 1
		clone_url := fmt.Sprintf("https://%s", url[i:])

		outdir := fmt.Sprintf("%s/%s", AZURE_PROJECTS_DIR, *r.Project.Name)
		os.MkdirAll(outdir, os.ModePerm)

		if len(AZURE_TOKEN) > 0 {
			err := DefaultGitCloneWithToken(clone_url, AZURE_TOKEN, outdir)
			if err != nil {
				log.Error(err)
				continue
			}
		}
	}
}

func (ac *AzureClient) DownloadRepos() error {
	log.Printf("[Azure DevOps] Downloading repositories")

	os.MkdirAll(AZURE_PROJECTS_DIR, os.ModePerm)

	workers := 10
	var wg sync.WaitGroup
	wg.Add(workers)

	repositories := make(chan git.GitRepository)

	for w := 0; w < workers; w++ {
		go ac.DownloadWorker(&wg, repositories)
	}

	repos, err := ac.g.GetRepositories(ac.ctx, git.GetRepositoriesArgs{})
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	for _, repo := range *repos {
		repositories <- repo
	}
	close(repositories)

	wg.Wait()

	return nil
}

func (ac *AzureClient) ListRepositories() error {
	log.Println("[Azure DevOps] Listing repositories")

	headers := table.Row{"REPOSITORY NAME", "ID"}
	results := []table.Row{}

	repos, err := ac.g.GetRepositories(ac.ctx, git.GetRepositoriesArgs{})
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	for _, repo := range *repos {
		results = append(results, table.Row{*(repo.Name), *(repo.Id)})
	}

	CreateTable(headers, results)

	return nil
}

func (ac *AzureClient) ListPipelines() error {
	log.Printf("[Azure DevOps] Listing pipelines")

	resp, err := ac.c.GetProjects(ac.ctx, core.GetProjectsArgs{})
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	results := []table.Row{}
	headers := table.Row{"PROJECT", "PIPELINE NAME"}
	for resp != nil {
		for _, project := range (*resp).Value {
			resp, err := ac.p.ListPipelines(ac.ctx, pipelines.ListPipelinesArgs{
				Project: project.Name,
			})
			if err != nil {
				return fmt.Errorf("err: %v", err)
			}

			for _, pipeline := range (*resp).Value {
				results = append(results, table.Row{*project.Name, *pipeline.Name})
			}
		}

		if resp.ContinuationToken != "" {
			args := core.GetProjectsArgs{
				ContinuationToken: &resp.ContinuationToken,
			}

			resp, err = ac.c.GetProjects(ac.ctx, args)
			if err != nil {
				return fmt.Errorf("err: %v", err)
			}
		} else {
			resp = nil
		}
	}

	CreateTable(headers, results)

	return nil
}

func (ac *AzureClient) ListBuilds() error {
	resp, err := ac.c.GetProjects(ac.ctx, core.GetProjectsArgs{})
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	headers := table.Row{"PROJECT", "TOTAL OF BUILDS"}
	results := []table.Row{}

	for resp != nil {
		for _, project := range (*resp).Value {
			builds, err := ac.b.GetBuilds(ac.ctx, build.GetBuildsArgs{
				Project: project.Name,
			})

			if err != nil {
				log.Errorf("error getting builds from project: %s - err: %v", project.Name, err)
				continue
			}

			results = append(results, table.Row{
				*project.Name,
				len(builds.Value),
			})
		}

		if resp.ContinuationToken != "" {
			args := core.GetProjectsArgs{
				ContinuationToken: &resp.ContinuationToken,
			}

			resp, err = ac.c.GetProjects(ac.ctx, args)
			if err != nil {
				return fmt.Errorf("err: %v", err)
			}
		} else {
			resp = nil
		}
	}

	CreateTable(headers, results)

	return nil
}

func (ac *AzureClient) GetBuildsOutputs() error {
	resp, err := ac.c.GetProjects(ac.ctx, core.GetProjectsArgs{})
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	for resp != nil {
		for _, project := range (*resp).Value {
			builds, err := ac.b.GetBuilds(ac.ctx, build.GetBuildsArgs{
				Project: project.Name,
			})

			if err != nil {
				log.Errorf("error getting builds from project: %s - err: %v", project.Name, err)
				continue
			}

			for _, b := range builds.Value {
				log.Printf("Getting logs from project: %s - build: %s", *project.Name, *b.BuildNumber)

				logs, err := ac.b.GetBuildLogs(ac.ctx, build.GetBuildLogsArgs{
					Project: project.Name,
					BuildId: b.Id,
				})

				if err != nil {
					log.Errorf("error getting build logs - err: %v", err)
					continue
				}

				logs_dir := fmt.Sprintf("%s/%s/%s", AZURE_LOGS_DIR, *project.Name, *b.BuildNumber)
				os.MkdirAll(logs_dir, os.ModePerm)

				for _, l := range *logs {
					lines, err := ac.b.GetBuildLogLines(ac.ctx, build.GetBuildLogLinesArgs{
						Project: project.Name,
						BuildId: b.Id,
						LogId:   l.Id,
					})

					if err != nil {
						log.Errorf("error getting log lines - err: %v", err)
						continue
					}

					log_path := fmt.Sprintf("%s/%d.txt", logs_dir, l.Id)

					log_output, err := os.OpenFile(log_path, os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						log.Errorf("error creating log file - err: %v", err)
					}

					writer := bufio.NewWriter(log_output)

					for _, line := range *lines {
						writer.WriteString(line + "\n")
					}

					writer.Flush()
					log_output.Close()
				}
			}
		}

		if resp.ContinuationToken != "" {
			args := core.GetProjectsArgs{
				ContinuationToken: &resp.ContinuationToken,
			}

			resp, err = ac.c.GetProjects(ac.ctx, args)
			if err != nil {
				return fmt.Errorf("err: %v", err)
			}
		} else {
			resp = nil
		}
	}

	return nil
}

func (ac *AzureClient) DownloadBuildsArtifacts() error {
	resp, err := ac.c.GetProjects(ac.ctx, core.GetProjectsArgs{})
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	for resp != nil {
		for _, project := range (*resp).Value {
			builds, err := ac.b.GetBuilds(ac.ctx, build.GetBuildsArgs{
				Project: project.Name,
			})

			if err != nil {
				log.Errorf("error getting builds from project: %s - err: %v", project.Name, err)
				continue
			}

			for _, b := range builds.Value {
				artifacts, err := ac.b.GetArtifacts(ac.ctx, build.GetArtifactsArgs{
					Project: project.Name,
					BuildId: b.Id,
				})

				if err != nil {
					log.Errorf("error getting artifacts - err: %v", err)
					continue
				}

				artifacts_dir := fmt.Sprintf("%s/%s/%s", AZURE_ARTIFACTS_DIR, *project.Name, *b.BuildNumber)
				os.MkdirAll(artifacts_dir, os.ModePerm)

				for _, artifact := range *artifacts {
					content, err := ac.b.GetArtifactContentZip(ac.ctx, build.GetArtifactContentZipArgs{
						Project:      project.Name,
						BuildId:      b.Id,
						ArtifactName: artifact.Name,
					})

					if err != nil {
						log.Errorf("error getting artifact content - err: %v", err)
						continue
					}

					data, err := ioutil.ReadAll(content)
					if err != nil {
						log.Errorf("error reading artifact - err: %v", err)
						continue
					}

					artifact_path := fmt.Sprintf("%s/%s", artifacts_dir, *artifact.Name)
					err = ioutil.WriteFile(artifact_path, data, 0644)
					if err != nil {
						log.Errorf("error saving artifact to local directory - err: %v", err)
					}

					log.Printf("Download finished - Project: %s - Build: %d - Artifact: %s", *project.Name, *b.Id, *artifact.Name)
				}
			}
		}

		if resp.ContinuationToken != "" {
			args := core.GetProjectsArgs{
				ContinuationToken: &resp.ContinuationToken,
			}

			resp, err = ac.c.GetProjects(ac.ctx, args)
			if err != nil {
				return fmt.Errorf("err: %v", err)
			}
		} else {
			resp = nil
		}
	}

	return nil
}

func (ac *AzureClient) GetVariableGroups() error {
	resp, err := ac.c.GetProjects(ac.ctx, core.GetProjectsArgs{})
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}

	for resp != nil {

		for _, project := range (*resp).Value {
			builds, err := ac.b.GetBuilds(ac.ctx, build.GetBuildsArgs{
				Project: project.Name,
			})

			if err != nil {
				log.Errorf("error getting builds from project: %s - err: %v", project.Name, err)
				continue
			}

			for _, b := range builds.Value {
				headers := table.Row{"PROJECT", "BUILD", "VARIABLE GROUP", "VARIABLE", "VALUE"}
				results := []table.Row{}

				log.Printf("Getting definition from project: %s - build: %s", *project.Name, *b.BuildNumber)

				def, err := ac.b.GetDefinition(ac.ctx, build.GetDefinitionArgs{
					Project:      project.Name,
					DefinitionId: b.Definition.Id,
				})

				if err != nil {
					log.Errorf("error getting build definition - err: %v", err)
					continue
				}

				if def.VariableGroups != nil {
					for _, varGroup := range *def.VariableGroups {
						for k, v := range *varGroup.Variables {
							results = append(results, table.Row{
								*project.Name,
								*b.BuildNumber,
								*varGroup.Name,
								k,
								*v.Value,
							})
						}

						projVarsBytes, err := json.Marshal(*varGroup.Variables)
						if err != nil {
							log.Errorf("error in JSON marshal - err: %v", err)
							continue
						}

						outdir := fmt.Sprintf("%s/%s/%s", AZURE_VARIABLES_DIR, *project.Name, *b.BuildNumber)
						os.MkdirAll(outdir, os.ModePerm)

						varsFile := fmt.Sprintf("%s/variable_groups.json", outdir)
						if err = ioutil.WriteFile(varsFile, projVarsBytes, 0644); err != nil {
							log.Errorf("error creating JSON file - err: %v", err)
						}
					}

					CreateTable(headers, results)
					fmt.Println()
				}
			}
		}

		if resp.ContinuationToken != "" {
			args := core.GetProjectsArgs{
				ContinuationToken: &resp.ContinuationToken,
			}

			resp, err = ac.c.GetProjects(ac.ctx, args)
			if err != nil {
				return fmt.Errorf("err: %v", err)
			}
		} else {
			resp = nil
		}
	}

	return nil
}

func NewAzureClient(cmd *cobra.Command, args []string) {
	var az AzureClient
	var conn *azuredevops.Connection

	ctx := context.Background()
	conn = azuredevops.NewPatConnection(AZURE_ORG_URL, AZURE_TOKEN)

	client, err := core.NewClient(ctx, conn)
	if err != nil {
		log.Fatal(err)
	}

	gclient, err := git.NewClient(ctx, conn)
	if err != nil {
		log.Fatal(err)
	}

	pclient := pipelines.NewClient(ctx, conn)

	fclient, err := feed.NewClient(ctx, conn)
	if err != nil {
		log.Fatal(err)
	}

	bclient, err := build.NewClient(ctx, conn)
	if err != nil {
		log.Fatal(err)
	}

	az.ctx = ctx
	az.c = client
	az.g = gclient
	az.p = pclient
	az.f = fclient
	az.b = bclient

	AZ = az
}

var azureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Interact with Azure DevOps",
	Long:  `Options for Azure DevOps Interaction`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

var azureListProjectsCmd = &cobra.Command{
	Use:    "list-projects",
	Short:  "List Projects",
	Long:   `List Projects`,
	PreRun: NewAzureClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := AZ.ListProjects()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var azureListReposCmd = &cobra.Command{
	Use:    "list-repos",
	Short:  "List Repositories",
	Long:   `List Repositories`,
	PreRun: NewAzureClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := AZ.ListRepositories()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var azureListPipelinesCmd = &cobra.Command{
	Use:    "list-pipelines",
	Short:  "List Pipelines",
	Long:   `List Pipelines`,
	PreRun: NewAzureClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := AZ.ListPipelines()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var azureListBuildsCmd = &cobra.Command{
	Use:    "list-builds",
	Short:  "List builds",
	Long:   `List builds`,
	PreRun: NewAzureClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := AZ.ListBuilds()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var azureGetBuildsCmd = &cobra.Command{
	Use:    "get-builds",
	Short:  "Get builds outputs",
	Long:   `Get builds outputs`,
	PreRun: NewAzureClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := AZ.GetBuildsOutputs()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var azureDownloadArtifactsCmd = &cobra.Command{
	Use:    "download-artifacts",
	Short:  "Download builds artifacts",
	Long:   `Download builds artifacts`,
	PreRun: NewAzureClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := AZ.DownloadBuildsArtifacts()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var azureDownloadReposCmd = &cobra.Command{
	Use:    "download-repos",
	Short:  "Download repositories",
	Long:   `Download repositories`,
	PreRun: NewAzureClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := AZ.DownloadRepos()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var azureListVarGroupsCmd = &cobra.Command{
	Use:    "list-var-groups",
	Short:  "List variable groups",
	Long:   `List variable groups`,
	PreRun: NewAzureClient,

	Run: func(cmd *cobra.Command, args []string) {
		err := AZ.GetVariableGroups()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(azureCmd)

	azureCmd.AddCommand(azureListProjectsCmd)
	azureCmd.AddCommand(azureListReposCmd)
	azureCmd.AddCommand(azureListPipelinesCmd)
	azureCmd.AddCommand(azureDownloadReposCmd)
	azureCmd.AddCommand(azureListBuildsCmd)
	azureCmd.AddCommand(azureGetBuildsCmd)
	azureCmd.AddCommand(azureDownloadArtifactsCmd)
	azureCmd.AddCommand(azureListVarGroupsCmd)

	azureCmd.PersistentFlags().StringVarP(&AZURE_ORG_URL, "org", "o", "", "Organization URL (Ex: https://dev.azure.com/myorg)")
	azureCmd.PersistentFlags().StringVarP(&AZURE_TOKEN, "token", "t", "", "Access Token")

	var err error

	if AZURE_PROJECTS_DIR, err = GetConfigParam("azure.projects"); err != nil {
		log.Fatal(err)
	}

	if AZURE_ARTIFACTS_DIR, err = GetConfigParam("azure.artifacts"); err != nil {
		log.Fatal(err)
	}

	if AZURE_LOGS_DIR, err = GetConfigParam("azure.logs"); err != nil {
		log.Fatal(err)
	}

	if AZURE_VARIABLES_DIR, err = GetConfigParam("azure.variables"); err != nil {
		log.Fatal(err)
	}
}
