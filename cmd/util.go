package cmd

import (
	"archive/tar"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
)

var (
	Black   = Color("\033[1;30m%s\033[0m")
	Red     = Color("\033[1;31m%s\033[0m")
	Green   = Color("\033[1;32m%s\033[0m")
	Yellow  = Color("\033[1;33m%s\033[0m")
	Purple  = Color("\033[1;34m%s\033[0m")
	Magenta = Color("\033[1;35m%s\033[0m")
	Teal    = Color("\033[1;36m%s\033[0m")
	White   = Color("\033[1;37m%s\033[0m")
)

type GitlabConfig struct {
	Projects  string `mapstructure:"projects"`
	Outputs   string `mapstructure:"outputs"`
	Workers   int    `mapstructure:"workers"`
	Variables string `mapstructure:"variables"`
}

type GithubConfig struct {
	Projects  string `mapstructure:"projects"`
	Workers   int    `mapstructure:"workers"`
	Workflows string `mapstructure:"workflows"`
	PageSize  int    `mapstructure:"pagesize"`
}

type SonarqubeConfig struct {
	Projects string `mapstructure:"projects"`
	Issues   string `mapstructure:"issues"`
}

type RegistryConfig struct {
	Images   string `mapstructure:"images"`
	Commands string `mapstructure:"commands"`
	Workers  int    `mapstructure:"workers"`
}

type JenkinsConfig struct {
	Artifacts string `mapstructure:"artifacts"`
	Outputs   string `mapstructure:"outputs"`
}

type NexusConfig struct {
	Repositories string `mapstructure:"repositories"`
}

type AzureConfig struct {
	Artifacts string `mapstructure:"artifacts"`
	Projects  string `mapstructure:"projects"`
	Logs      string `mapstructure:"logs"`
	Variables string `mapstructure:"variables"`
}

type GiteaConfig struct {
	Projects string `mapstructure:"projects"`
}

type ArtifactoryConfig struct {
	Repositories string `mapstructure:"repositories"`
	Docker       string `mapstructure:"docker"`
	Workers      int    `mapstructure:"workers"`
}

type TerraformConfig struct {
	Organizations string `mapstructure:"organizations"`
}

type EpyonConfig struct {
	Gitlab      map[string]GitlabConfig      `mapstructure:"gitlab"`
	Github      map[string]GithubConfig      `mapstructure:"github"`
	Sonarqube   map[string]SonarqubeConfig   `mapstructure:"sonarqube"`
	Registry    map[string]RegistryConfig    `mapstructure:"registry"`
	Jenkins     map[string]JenkinsConfig     `mapstructure:"jenkins"`
	Nexus       map[string]NexusConfig       `mapstructure:"nexus"`
	Azure       map[string]AzureConfig       `mapstructure:"azure"`
	Gitea       map[string]GiteaConfig       `mapstructure:"gitea"`
	Artifactory map[string]ArtifactoryConfig `mapstructure:"artifactory"`
	Terraform   map[string]TerraformConfig   `mapstructure:"terraform"`
}

func CreateTable(header table.Row, results []table.Row) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(header)
	t.AppendRows(results)
	t.SetStyle(table.StyleLight)
	t.Render()
}

func Color(colorString string) func(...interface{}) string {
	sprint := func(args ...interface{}) string {
		return fmt.Sprintf(colorString, fmt.Sprint(args...))
	}
	return sprint
}

func Untar(src string, dst string) error {
	r, err := os.Open(src)
	if err != nil {
		return nil
	}

	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()

		switch {

		case err == io.EOF:
			return nil

		case err != nil:
			return err

		case header == nil:
			continue
		}

		target := filepath.Join(dst, header.Name)

		switch header.Typeflag {

		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}

		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			if _, err := io.Copy(f, tr); err != nil {
				return err
			}

			f.Close()
		}
	}
}

func GitCloneWithUserPass(repo_url string, user string, password string, outdir string) error {
	customClient, err := NewHttpClient()
	if err != nil {
		return err
	}

	if strings.Contains(repo_url, "https://") {
		client.InstallProtocol("https", githttp.NewClient(customClient))
	} else {
		client.InstallProtocol("http", githttp.NewClient(customClient))
	}

	_, err = git.PlainClone(outdir, false, &git.CloneOptions{
		URL:      repo_url,
		Progress: nil,
		Auth: &githttp.BasicAuth{
			Username: user,
			Password: password,
		},
	})

	if err != nil {
		return fmt.Errorf("error in git clone - err: %v", err)
	}

	return nil
}

func GitCloneWithToken(repo_url string, token string, outdir string) error {
	customClient, err := NewHttpClient()
	if err != nil {
		return err
	}

	if strings.Contains(repo_url, "https://") {
		client.InstallProtocol("https", githttp.NewClient(customClient))
	} else {
		client.InstallProtocol("http", githttp.NewClient(customClient))
	}

	_, err = git.PlainClone(outdir, false, &git.CloneOptions{
		URL:      repo_url,
		Progress: nil,
		Auth: &githttp.BasicAuth{
			Username: "oauth2",
			Password: token,
		},
		InsecureSkipTLS: true,
	})

	if err != nil {
		return fmt.Errorf("error in git clone - err: %v", err)
	}

	return nil
}

func DefaultGitCloneWithToken(repo_url string, token string, outdir string, server_type string) error {
	var cmd *exec.Cmd

	switch server_type {
	case "azure":
		basic_token := fmt.Sprintf(":%s", token)
		b64_token := base64.StdEncoding.EncodeToString([]byte(basic_token))
		authorization := fmt.Sprintf("Authorization: Basic %s", b64_token)

		cmd = exec.Command("git", "clone", repo_url)
		cmd.Args = append(cmd.Args, "--config", fmt.Sprintf("http.extraHeader=%s", authorization))
	case "github":
		clone_url := strings.Replace(
			repo_url,
			"://",
			fmt.Sprintf("://%s@", token),
			-1,
		)
		cmd = exec.Command("git", "clone", clone_url)
	default:
		return fmt.Errorf("undefined server type for git clone")
	}

	if SSL_INSECURE {
		cmd.Args = append(cmd.Args, "--config", "http.sslverify=false")
	}

	if len(PROXY_SERVER) > 0 {
		if len(PROXY_USER) > 0 {
			if strings.Contains(PROXY_SERVER, "http://") {
				PROXY_SERVER = strings.Replace(
					PROXY_SERVER,
					"http://",
					fmt.Sprintf("http://%s:%s@", PROXY_USER, PROXY_PASS),
					1,
				)
			}
		}

		proxyURL, err := url.Parse(PROXY_SERVER)
		if err != nil {
			return fmt.Errorf("error parsing proxy url - err: %v", err)
		}

		proxyConfig := fmt.Sprintf("http.proxy=%s", proxyURL)
		cmd.Args = append(cmd.Args, "--config", proxyConfig)
	}

	cmd.Dir = outdir
	cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=0")

	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("error in git clone - err: %v", err)
	}

	log.Printf("Download finished - Clone URL: %s", repo_url)

	return nil
}

func GetConfigParam(name string) (string, error) {
	viper.SetConfigFile("config.yaml")

	err := viper.ReadInConfig()
	if err != nil {
		return "", fmt.Errorf("error in ReadInConfig - err: %v", err)
	}

	value := viper.GetString(name)
	if len(value) == 0 {
		return "", fmt.Errorf("empty config parameter: %s", name)
	}

	return value, nil
}

func GetConfigParamInt(name string) (int, error) {
	var intValue int

	viper.SetConfigFile("config.yaml")

	err := viper.ReadInConfig()
	if err != nil {
		return intValue, fmt.Errorf("error in ReadInConfig - err: %v", err)
	}

	value := viper.GetString(name)
	if len(value) == 0 {
		return intValue, fmt.Errorf("empty config parameter: %s", name)
	}

	if intValue, err = strconv.Atoi(value); err != nil {
		return intValue, fmt.Errorf("error converting string to int value: %s", err)
	}

	return intValue, nil
}

func NewHttpClient() (*http.Client, error) {
	client := &http.Client{}

	tr := &http.Transport{
		TLSHandshakeTimeout: 30 * time.Second,
	}

	if len(PROXY_SERVER) > 0 {
		if len(PROXY_USER) > 0 {
			if strings.Contains(PROXY_SERVER, "http://") {
				PROXY_SERVER = strings.Replace(
					PROXY_SERVER,
					"http://",
					fmt.Sprintf("http://%s:%s@", PROXY_USER, PROXY_PASS),
					1,
				)
			}
		}

		proxyURL, err := url.Parse(PROXY_SERVER)
		if err != nil {
			return client, fmt.Errorf("error parsing proxy url - err: %v", err)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	if len(SOCKS_SERVER) > 0 {
		dialer, err := proxy.SOCKS5("tcp", SOCKS_SERVER, nil, proxy.Direct)
		if err != nil {
			return client, fmt.Errorf("error creating socks dialer - err: %v", err)
		}
		tr.Dial = dialer.Dial
	}

	if SSL_INSECURE {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client.Transport = tr

	return client, nil
}
