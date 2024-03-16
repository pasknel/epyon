package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/hashicorp/go-tfe"
	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	TF_TOKEN            string
	TF_SERVER           string
	TF_ORGANIZATION     string
	TF_ORGANIZATION_DIR string
	TF_WORKSPACE        string
	TF_CLIENT           TfClient
)

type TfClient struct {
	Client *tfe.Client
}

func (t *TfClient) ListWorkspaceResources(workspace string) error {
	resources, err := t.Client.WorkspaceResources.List(context.Background(), workspace, nil)
	if err != nil {
		return fmt.Errorf("error listing workspace resources - err: %v", err)
	}

	log.Printf("[Terraform] Workspace: %s - Total of Resources: %d", workspace, resources.TotalCount)

	header := table.Row{"ID", "NAME", "PROVIDER"}
	rows := []table.Row{}

	for _, r := range resources.Items {
		rows = append(rows, table.Row{
			r.ID,
			r.Name,
			r.Provider,
		})
	}

	CreateTable(header, rows)

	return nil
}

func (t *TfClient) ListVariableSets(org string) error {
	varsets, err := t.Client.VariableSets.List(context.Background(), org, nil)
	if err != nil {
		return fmt.Errorf("error listing variable sets - err: %v", err)
	}

	for _, varset := range varsets.Items {
		log.Printf("[Terraform] Variable set: %s", varset.Name)

		header := table.Row{"ID", "KEY", "VALUE", "SENSITIVE", "CATEGORY"}
		rows := []table.Row{}

		for _, v := range varset.Variables {
			var_info, err := t.Client.VariableSetVariables.Read(context.Background(), varset.ID, v.ID)
			if err != nil {
				log.Errorf("error getting variable info - err: %s", err)
			}

			rows = append(rows, table.Row{
				var_info.ID,
				var_info.Key,
				var_info.Value,
				var_info.Sensitive,
				var_info.Category,
			})
		}

		CreateTable(header, rows)
	}

	return nil
}

func (t *TfClient) GetWorkspaceVariables(org string, workspace string) error {
	vars, err := t.Client.Variables.List(context.Background(), workspace, nil)
	if err != nil {
		return fmt.Errorf("error listing workspace variables - err: %v", err)
	}

	log.Printf("[Terraform] Workspace ID: %s - Listing Variables", workspace)

	header := table.Row{"ID", "KEY", "SENSITIVE", "VALUE"}
	rows := []table.Row{}

	for _, v := range vars.Items {
		rows = append(rows, table.Row{
			v.ID,
			v.Key,
			v.Sensitive,
			v.Value,
		})
	}

	outdir := fmt.Sprintf("%s/%s/%s", TF_ORGANIZATION_DIR, org, workspace)
	os.MkdirAll(outdir, os.ModePerm)

	workspaceVarsBytes, _ := json.Marshal(vars.Items)

	varsFile := fmt.Sprintf("%s/workspace_variables.json", outdir)
	if err = os.WriteFile(varsFile, workspaceVarsBytes, 0644); err != nil {
		log.Errorf("error creating JSON file - err: %v", err)
	}

	CreateTable(header, rows)

	fmt.Println()

	return nil
}

func (t *TfClient) ListAgents(org string) error {
	pools, err := t.Client.AgentPools.List(context.Background(), org, nil)
	if err != nil {
		return fmt.Errorf("error listing agent pools - err: %v", err)
	}

	log.Printf("[Terraform] Total of agent pools: %d", pools.TotalCount)

	header := table.Row{"POOL ID", "AGENT ID", "AGENT NAME", "AGENT IP"}
	rows := []table.Row{}

	for _, p := range pools.Items {
		agents, err := t.Client.Agents.List(context.Background(), p.ID, nil)
		if err != nil {
			log.Errorf("error listing agents from pool %s", p.ID)
			continue
		}

		for _, agent := range agents.Items {
			rows = append(rows, table.Row{
				p.ID,
				agent.ID,
				agent.Name,
				agent.IP,
			})
		}
	}

	CreateTable(header, rows)

	return nil
}

func (t *TfClient) ListWorkspaceVariables(org string) error {
	opts := tfe.WorkspaceListOptions{
		ListOptions: tfe.ListOptions{
			PageNumber: 0,
		},
	}

	for {
		workspaces, err := t.Client.Workspaces.List(context.Background(), org, &opts)
		if err != nil {
			return fmt.Errorf("error listing workspaces - err: %v", err)
		}

		for p := 0; p < workspaces.TotalPages; p++ {
			for _, w := range workspaces.Items {
				if err := t.GetWorkspaceVariables(org, w.ID); err != nil {
					log.Error(err)
				}
			}
		}

		if workspaces.CurrentPage >= workspaces.TotalPages {
			break
		}

		opts.PageNumber++
	}

	return nil
}

func (t *TfClient) ListWorkspaces(org string) error {
	log.Printf("[Terraform] Listing Workspaces")

	opts := tfe.WorkspaceListOptions{
		ListOptions: tfe.ListOptions{
			PageNumber: 0,
		},
	}

	header := table.Row{"ID", "NAME"}
	rows := []table.Row{}
	print_total := true

	for {
		workspaces, err := t.Client.Workspaces.List(context.Background(), org, &opts)
		if err != nil {
			return fmt.Errorf("error listing workspaces - err: %v", err)
		}

		if print_total {
			log.Printf("[Terraform] Total of Workspaces: %d", workspaces.TotalCount)
			print_total = false
		}

		for p := 0; p < workspaces.TotalPages; p++ {
			for _, w := range workspaces.Items {
				rows = append(rows, table.Row{
					w.ID,
					w.Name,
				})
			}
		}

		if workspaces.CurrentPage >= workspaces.TotalPages {
			break
		}

		opts.PageNumber++
	}

	CreateTable(header, rows)

	return nil
}

func (t *TfClient) ListTeams(org string) error {
	log.Printf("[Terraform] Listing Teams")

	teams, err := t.Client.Teams.List(context.Background(), org, nil)
	if err != nil {
		return fmt.Errorf("error listing teams - err: %v", err)

	}

	log.Printf("[Terraform] Total of teams: %d", teams.TotalCount)

	header := table.Row{"ID", "NAME", "MEMBERS COUNT"}
	rows := []table.Row{}

	for _, team := range teams.Items {
		rows = append(rows, table.Row{
			team.ID,
			team.Name,
			team.UserCount,
		})
	}

	CreateTable(header, rows)

	return nil
}

func (t *TfClient) ListTeamsMembers(org string) error {
	log.Printf("[Terraform] Listing Teams Members")

	teams, err := t.Client.Teams.List(context.Background(), org, nil)
	if err != nil {
		return fmt.Errorf("error listing teams - err: %v", err)

	}

	for _, team := range teams.Items {
		header := table.Row{"ID", "USERNAME", "EMAIL"}
		rows := []table.Row{}

		log.Printf("[Terraform] Team: %s", team.Name)

		users, err := t.Client.TeamMembers.ListUsers(context.Background(), team.ID)
		if err != nil {
			log.Error(err)
			continue
		}

		for _, u := range users {
			rows = append(rows, table.Row{
				u.ID,
				u.Username,
				u.Email,
			})
		}

		CreateTable(header, rows)
	}

	return nil
}

func (t *TfClient) ListProjects(org string) error {
	log.Printf("[Terraform] Listing Projects")

	projects, err := t.Client.Projects.List(context.Background(), org, nil)
	if err != nil {
		return fmt.Errorf("error listing projects - err: %v", err)
	}

	log.Printf("[Terraform] Total of projects: %d", projects.TotalCount)

	header := table.Row{"ID", "NAME", "ORGANIZATION"}
	rows := []table.Row{}

	for _, p := range projects.Items {
		rows = append(rows, table.Row{
			p.ID,
			p.Name,
			org,
		})
	}

	CreateTable(header, rows)

	return nil
}

func (t *TfClient) ListOrgs() error {
	log.Printf("[Terraform] Listing Organizations")

	orgs, err := t.Client.Organizations.List(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("error listing organizations - err: %v", err)
	}

	header := table.Row{"NAME", "EMAIL", "EXTERNAL ID"}
	rows := []table.Row{}

	for _, org := range orgs.Items {
		rows = append(rows, table.Row{
			org.Name,
			org.Email,
			org.ExternalID,
		})
	}

	CreateTable(header, rows)

	return nil
}

func (t *TfClient) DownloadState(org string, workspace string, downloadURL string) error {
	client, err := NewHttpClient()
	if err != nil {
		return err
	}

	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return fmt.Errorf("error creating http request - err: %v", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", TF_TOKEN))

	rsp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending http request - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return fmt.Errorf("error reading http response - err: %v", err)
	}

	outdir := fmt.Sprintf("%s/%s/%s", TF_ORGANIZATION_DIR, org, workspace)
	os.MkdirAll(outdir, os.ModePerm)

	stateFile := fmt.Sprintf("%s/current_state.json", outdir)
	if err = os.WriteFile(stateFile, data, 0644); err != nil {
		log.Errorf("error creating state file - err: %v", err)
	}

	log.Printf("[Terraform] Workspace: %s - State file saved: %s", workspace, stateFile)

	return nil
}

func (t *TfClient) GetCurrentState(org string, workspace string) error {
	log.Printf("[Terraform] Reading current state - Workspace: %s", workspace)

	state, err := t.Client.StateVersions.ReadCurrent(context.Background(), workspace)
	if err != nil {
		return fmt.Errorf("error reading current state - err: %v", err)
	}

	if err := t.DownloadState(org, workspace, state.DownloadURL); err != nil {
		return err
	}

	return nil
}

func (t *TfClient) DownloadCurrentStates(org string) error {
	opts := tfe.WorkspaceListOptions{
		ListOptions: tfe.ListOptions{
			PageNumber: 0,
		},
	}

	for {
		workspaces, err := t.Client.Workspaces.List(context.Background(), org, &opts)
		if err != nil {
			return fmt.Errorf("error listing workspaces - err: %v", err)
		}

		for p := 0; p < workspaces.TotalPages; p++ {
			for _, w := range workspaces.Items {
				if err := t.GetCurrentState(org, w.ID); err != nil {
					log.Error(err)
				}
			}
		}

		if workspaces.CurrentPage >= workspaces.TotalPages {
			break
		}

		opts.PageNumber++
	}

	return nil
}

func NewTerraformClient(cmd *cobra.Command, args []string) {
	config := &tfe.Config{
		Address:           TF_SERVER,
		Token:             TF_TOKEN,
		RetryServerErrors: true,
	}

	c, err := tfe.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	TF_CLIENT = TfClient{
		Client: c,
	}
}

var tfListOrgsCmd = &cobra.Command{
	Use:    "list-orgs",
	Short:  "List organizations",
	Long:   `List organizations`,
	PreRun: NewTerraformClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := TF_CLIENT.ListOrgs(); err != nil {
			log.Fatal(err)
		}
	},
}

var tfListProjectsCmd = &cobra.Command{
	Use:    "list-projects",
	Short:  "List projects",
	Long:   `List projects`,
	PreRun: NewTerraformClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := TF_CLIENT.ListProjects(TF_ORGANIZATION); err != nil {
			log.Fatal(err)
		}
	},
}

var tfListTeamsCmd = &cobra.Command{
	Use:    "list-teams",
	Short:  "List teams",
	Long:   `List teams`,
	PreRun: NewTerraformClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := TF_CLIENT.ListTeams(TF_ORGANIZATION); err != nil {
			log.Fatal(err)
		}
	},
}

var tfListTeamsMembersCmd = &cobra.Command{
	Use:    "list-teams-members",
	Short:  "List teams members",
	Long:   `List teams members`,
	PreRun: NewTerraformClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := TF_CLIENT.ListTeamsMembers(TF_ORGANIZATION); err != nil {
			log.Fatal(err)
		}
	},
}

var tfListWorkspacesCmd = &cobra.Command{
	Use:    "list-workspaces",
	Short:  "List workspaces",
	Long:   `List workspaces`,
	PreRun: NewTerraformClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := TF_CLIENT.ListWorkspaces(TF_ORGANIZATION); err != nil {
			log.Fatal(err)
		}
	},
}

var tfListWorkspacesVariablesCmd = &cobra.Command{
	Use:    "list-workspaces-vars",
	Short:  "List workspaces variables",
	Long:   `List workspaces variables`,
	PreRun: NewTerraformClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := TF_CLIENT.ListWorkspaceVariables(TF_ORGANIZATION); err != nil {
			log.Fatal(err)
		}
	},
}

var tfListWorkspaceResourcesCmd = &cobra.Command{
	Use:    "list-workspaces-resources",
	Short:  "List workspace resources",
	Long:   `List workspace resources`,
	PreRun: NewTerraformClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := TF_CLIENT.ListWorkspaceResources(TF_WORKSPACE); err != nil {
			log.Fatal(err)
		}
	},
}

var tfListVarsSetCmd = &cobra.Command{
	Use:    "list-vars-set",
	Short:  "List variable sets",
	Long:   `List variable sets`,
	PreRun: NewTerraformClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := TF_CLIENT.ListVariableSets(TF_ORGANIZATION); err != nil {
			log.Fatal(err)
		}
	},
}

var tfListAgentsCmd = &cobra.Command{
	Use:    "list-agents",
	Short:  "List agents",
	Long:   `List agents`,
	PreRun: NewTerraformClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := TF_CLIENT.ListAgents(TF_ORGANIZATION); err != nil {
			log.Fatal(err)
		}
	},
}

var tfDownloadCurrentStatesCmd = &cobra.Command{
	Use:    "get-workspaces-states",
	Short:  "Download the current state of each workspace",
	Long:   `Download the current state of each workspace`,
	PreRun: NewTerraformClient,

	Run: func(cmd *cobra.Command, args []string) {
		if err := TF_CLIENT.DownloadCurrentStates(TF_ORGANIZATION); err != nil {
			log.Fatal(err)
		}
	},
}

var terraformCmd = &cobra.Command{
	Use:   "terraform",
	Short: "Interact with Terraform Cloud/Enterprise",
	Long:  `Interact with Terraform Cloud/Enterprise`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

func init() {
	rootCmd.AddCommand(terraformCmd)

	terraformCmd.AddCommand(tfListOrgsCmd)
	terraformCmd.AddCommand(tfListProjectsCmd)
	terraformCmd.AddCommand(tfListTeamsCmd)
	terraformCmd.AddCommand(tfListWorkspacesCmd)
	terraformCmd.AddCommand(tfListWorkspacesVariablesCmd)
	terraformCmd.AddCommand(tfListVarsSetCmd)
	terraformCmd.AddCommand(tfListAgentsCmd)
	terraformCmd.AddCommand(tfListWorkspaceResourcesCmd)
	terraformCmd.AddCommand(tfListTeamsMembersCmd)
	terraformCmd.AddCommand(tfDownloadCurrentStatesCmd)

	terraformCmd.PersistentFlags().StringVarP(&TF_SERVER, "server", "s", "", "Server Address")
	terraformCmd.PersistentFlags().StringVarP(&TF_TOKEN, "token", "t", "", "Token")

	tfListProjectsCmd.Flags().StringVarP(&TF_ORGANIZATION, "org", "o", "", "Organization")
	tfListTeamsCmd.Flags().StringVarP(&TF_ORGANIZATION, "org", "o", "", "Organization")
	tfListWorkspacesCmd.Flags().StringVarP(&TF_ORGANIZATION, "org", "o", "", "Organization")
	tfListWorkspacesVariablesCmd.Flags().StringVarP(&TF_ORGANIZATION, "org", "o", "", "Organization")
	tfListVarsSetCmd.Flags().StringVarP(&TF_ORGANIZATION, "org", "o", "", "Organization")
	tfListAgentsCmd.Flags().StringVarP(&TF_ORGANIZATION, "org", "o", "", "Organization")
	tfListWorkspaceResourcesCmd.Flags().StringVarP(&TF_WORKSPACE, "workspace", "w", "", "Workspace ID")
	tfListTeamsMembersCmd.Flags().StringVarP(&TF_ORGANIZATION, "org", "o", "", "Organization")
	tfDownloadCurrentStatesCmd.Flags().StringVarP(&TF_ORGANIZATION, "org", "o", "", "Organization")

	var err error

	if TF_ORGANIZATION_DIR, err = GetConfigParam("terraform.organizations"); err != nil {
		log.Fatal(err)
	}
}
