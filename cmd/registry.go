package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/jedib0t/go-pretty/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	REGISTRY_SERVER      string
	REGISTRY_USER        string
	REGISTRY_PASS        string
	REGISTRY_TOKEN       string
	IMAGE_NAME           string
	IMAGE_LATEST         bool
	REGISTRY_WORKERS     int
	REGISTRY_IMAGES      string
	REGISTRY_COMMANDS    string
	REGISTRY_SERVER_TYPE string
)

type Repo struct {
	Repositories []string `json:"repositories"`
}

type Tags struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type DockerManifest struct {
	Version int                 `json:"schemaVersion"`
	Name    string              `json:"name"`
	Tag     string              `json:"tag"`
	Arch    string              `json:"architecture"`
	Layers  []map[string]string `json:"fsLayers"`
	History []DockerfileHistory `json:"history"`
}

type DockerfileHistory struct {
	Command string `json:"v1Compatibility"`
}

type DockerImageConfig struct {
	Commands []string `json:"Cmd"`
}

type DockerCommand struct {
	Id        string            `json:"id"`
	Created   string            `json:"created"`
	Parent    string            `json:"parent"`
	Throwaway bool              `json:"throwaway"`
	Config    DockerImageConfig `json:"container_config"`
}

type NexusManifest struct {
	MediaType     string            `json:"mediaType"`
	SchemaVersion int               `json:"schemaVersion"`
	Config        NexusImageLayer   `json:"config"`
	Layers        []NexusImageLayer `json:"layers"`
}

type NexusImageLayer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

type NexusImageConfig struct {
	Created      string              `json:"created"`
	Architecture string              `json:"architecture"`
	OS           string              `json:"os"`
	History      []NexusImageCommand `json:"history"`
}

type NexusImageCommand struct {
	Created    string `json:"created"`
	CreatedBy  string `json:"created_by"`
	Comment    string `json:"comment"`
	EmptyLayer bool   `json:"empty_layer"`
}

func GetFsLayers(image string, tag string) ([]string, error) {
	digests := []string{}

	url := fmt.Sprintf("%s/v2/%s/manifests/%s", strings.TrimSuffix(REGISTRY_SERVER, "/"), image, tag)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return digests, fmt.Errorf("error in new request - err: %v", err)
	}

	if len(REGISTRY_USER) > 0 {
		req.SetBasicAuth(REGISTRY_USER, REGISTRY_PASS)
	} else if len(REGISTRY_TOKEN) > 0 {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", REGISTRY_TOKEN))
	}

	client, err := NewHttpClient()
	if err != nil {
		return digests, err
	}

	rsp, err := client.Do(req)
	if err != nil {
		return digests, fmt.Errorf("error sending request - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return digests, fmt.Errorf("error reading response - err: %v", err)
	}

	if strings.Compare(REGISTRY_SERVER_TYPE, "Docker") == 0 {
		var manifest DockerManifest

		if err := json.Unmarshal(data, &manifest); err != nil {
			return digests, fmt.Errorf("error in JSON decoding - err: %v", err)
		}

		for _, layer := range manifest.Layers {
			digests = append(digests, layer["blobSum"])
		}
	} else {
		var manifest NexusManifest

		if err := json.Unmarshal(data, &manifest); err != nil {
			return digests, fmt.Errorf("error in JSON decoding - err: %v", err)
		}

		for _, layer := range manifest.Layers {
			digests = append(digests, layer.Digest)
		}
	}

	return digests, nil
}

func GetImageList() ([]string, error) {
	images := []string{}

	url := fmt.Sprintf("%s/v2/_catalog", strings.TrimSuffix(REGISTRY_SERVER, "/"))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return images, fmt.Errorf("error in new request - err: %v", err)
	}

	if len(REGISTRY_USER) > 0 {
		req.SetBasicAuth(REGISTRY_USER, REGISTRY_PASS)
	}

	client, err := NewHttpClient()
	if err != nil {
		return images, err
	}

	rsp, err := client.Do(req)
	if err != nil {
		return images, fmt.Errorf("error sending request - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return images, fmt.Errorf("error reading response - err: %v", err)
	}

	var repos Repo
	if err := json.Unmarshal(data, &repos); err != nil {
		return images, fmt.Errorf("error in json unmarshal - err: %v", err)
	}

	images = append(images, repos.Repositories...)

	return images, nil
}

func GetImageTags(image string) ([]string, error) {
	tags := []string{}

	url := fmt.Sprintf("%s/v2/%s/tags/list", strings.TrimSuffix(REGISTRY_SERVER, "/"), image)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return tags, fmt.Errorf("error in new request - err: %v", err)
	}

	if len(REGISTRY_USER) > 0 {
		req.SetBasicAuth(REGISTRY_USER, REGISTRY_PASS)
	} else if len(REGISTRY_TOKEN) > 0 {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", REGISTRY_TOKEN))
	}

	client, err := NewHttpClient()
	if err != nil {
		return tags, err
	}

	rsp, err := client.Do(req)
	if err != nil {
		return tags, fmt.Errorf("error sending request - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return tags, fmt.Errorf("error reading response - err: %v", err)
	}

	var t Tags
	if err := json.Unmarshal(data, &t); err != nil {
		return tags, fmt.Errorf("error in json unmarshal - err: %v", err)
	}

	tags = append(tags, t.Tags...)

	return tags, nil
}

func DownloadBlob(image string, digest string, tag string) error {
	blob_endpoint := fmt.Sprintf("%s/v2/%s/blobs/%s", strings.TrimSuffix(REGISTRY_SERVER, "/"), image, digest)

	req, err := http.NewRequest("GET", blob_endpoint, nil)
	if err != nil {
		return fmt.Errorf("error in new request - err: %v", err)
	}

	if len(REGISTRY_USER) > 0 {
		req.SetBasicAuth(REGISTRY_USER, REGISTRY_PASS)
	} else if len(REGISTRY_TOKEN) > 0 {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", REGISTRY_TOKEN))
	}

	client, err := NewHttpClient()
	if err != nil {
		return err
	}

	rsp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request - err: %v", err)
	}
	defer rsp.Body.Close()

	outdir := fmt.Sprintf("%s/%s/%s/", REGISTRY_IMAGES, image, tag)
	os.MkdirAll(outdir, os.ModePerm)

	outfile := fmt.Sprintf("%s/%s/%s/%s.tar.gz", REGISTRY_IMAGES, image, tag, digest[7:])
	out, err := os.Create(outfile)
	if err != nil {
		return fmt.Errorf("error creating file - err: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, rsp.Body)
	if err != nil {
		return fmt.Errorf("error saving file - err: %v", err)
	}

	log.WithFields(log.Fields{
		"image":  image,
		"tag":    tag,
		"digest": digest,
	}).Info("Download finished")

	Untar(outfile, outdir)

	os.Remove(outfile)

	return nil
}

func DownloadWorker(images chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for img := range images {
		image_tags, err := GetImageTags(img)
		if err != nil {
			log.Error(err)
			continue
		}

		tags := []string{}
		if IMAGE_LATEST {
			tags = append(tags, image_tags[len(image_tags)-1])
		} else {
			tags = append(tags, image_tags...)
		}

		for _, tag := range tags {
			layers, err := GetFsLayers(img, tag)
			if err != nil {
				log.Error(err)
				continue
			}

			for _, digest := range layers {
				if err := DownloadBlob(img, digest, tag); err != nil {
					log.Error(err)
				}
			}
		}
	}
}

func GetCommandHistory(image string, tag string) ([]string, error) {
	commands := []string{}

	url := fmt.Sprintf("%s/v2/%s/manifests/%s", strings.TrimSuffix(REGISTRY_SERVER, "/"), image, tag)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return commands, fmt.Errorf("error in new request - err: %v", err)
	}

	if len(REGISTRY_USER) > 0 {
		req.SetBasicAuth(REGISTRY_USER, REGISTRY_PASS)
	}

	client, err := NewHttpClient()
	if err != nil {
		return commands, err
	}

	rsp, err := client.Do(req)
	if err != nil {
		return commands, fmt.Errorf("error sending request - err: %v", err)
	}
	defer rsp.Body.Close()

	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return commands, fmt.Errorf("error reading response - err: %v", err)
	}

	if strings.Compare(REGISTRY_SERVER_TYPE, "Docker") == 0 {
		var manifest DockerManifest

		if err := json.Unmarshal(data, &manifest); err != nil {
			return commands, fmt.Errorf("error in JSON decoding - err: %v", err)
		}

		for _, h := range manifest.History {
			dc := DockerCommand{}

			err := json.Unmarshal([]byte(h.Command), &dc)
			if err != nil {
				log.Errorf("error in JSON Unmarshal - err: %v", err)
				continue
			}

			for _, cmd := range dc.Config.Commands {
				prefix := []string{"/bin/sh -c #(nop)", "/bin/sh -c"}

				for _, p := range prefix {
					if strings.HasPrefix(cmd, p) {
						cmd = strings.TrimPrefix(cmd, p)
						cmd = strings.TrimSpace(cmd)
						if strings.Compare(p, "/bin/sh -c") == 0 {
							cmd = "RUN " + cmd
						}
					}
				}

				if VERBOSE {
					log.WithFields(log.Fields{
						"image":   image,
						"tag":     tag,
						"command": cmd,
					}).Info("Dockerfile Command")
				}

				commands = append(commands, cmd)
			}
		}
	} else {
		var manifest NexusManifest

		if err := json.Unmarshal(data, &manifest); err != nil {
			return commands, fmt.Errorf("error in JSON decoding - err: %v", err)
		}

		url := fmt.Sprintf("%s/v2/%s/blobs/%s", strings.TrimSuffix(REGISTRY_SERVER, "/"), image, manifest.Config.Digest)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return commands, fmt.Errorf("error in new request - err: %v", err)
		}

		if len(REGISTRY_USER) > 0 {
			req.SetBasicAuth(REGISTRY_USER, REGISTRY_PASS)
		}

		client, err := NewHttpClient()
		if err != nil {
			return commands, err
		}

		rsp, err := client.Do(req)
		if err != nil {
			return commands, fmt.Errorf("error sending request - err: %v", err)
		}
		defer rsp.Body.Close()

		data, err := io.ReadAll(rsp.Body)
		if err != nil {
			return commands, fmt.Errorf("error reading response - err: %v", err)
		}

		var config NexusImageConfig
		if err := json.Unmarshal(data, &config); err != nil {
			return commands, fmt.Errorf("error during json unmarshal - err: %v", err)
		}

		for _, h := range config.History {
			cmd := h.CreatedBy

			prefix := []string{"/bin/sh -c #(nop)", "/bin/sh -c"}

			for _, p := range prefix {
				if strings.HasPrefix(cmd, p) {
					cmd = strings.TrimPrefix(cmd, p)
					cmd = strings.TrimSpace(cmd)
					if strings.Compare(p, "/bin/sh -c") == 0 {
						cmd = "RUN " + cmd
					}
				}
			}

			if VERBOSE {
				log.WithFields(log.Fields{
					"image":   image,
					"tag":     tag,
					"command": cmd,
				}).Info("Dockerfile Command")
			}

			commands = append(commands, cmd)
		}
	}

	return commands, nil
}

var registryListImagesCmd = &cobra.Command{
	Use:   "list-images",
	Short: "List Container Images",
	Long:  `List Container Images`,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Registry] Listing Docker Images")

		header := table.Row{"Images"}
		rows := []table.Row{}

		images, err := GetImageList()
		if err != nil {
			log.Fatal(err)
		}

		for _, img := range images {
			rows = append(rows, table.Row{img})
		}

		CreateTable(header, rows)
	},
}

var registryListTagsCmd = &cobra.Command{
	Use:   "list-tags",
	Short: "List Image Tags",
	Long:  `List Image Tags`,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Registry] Listing image tags")

		images := []string{}
		var err error

		if len(IMAGE_NAME) > 0 {
			images = append(images, IMAGE_NAME)
		} else {
			images, err = GetImageList()
			if err != nil {
				log.Fatal(err)
			}
		}

		for _, img := range images {
			log.Printf("[Registry] Image: %s", img)

			header := table.Row{"Image", "Tag"}
			rows := []table.Row{}

			tags, err := GetImageTags(img)
			if err != nil {
				log.Error(err)
				continue
			}

			for _, tag := range tags {
				rows = append(rows, table.Row{img, tag})
			}

			CreateTable(header, rows)

			fmt.Println()
		}
	},
}

var registryDownloadImagesCmd = &cobra.Command{
	Use:   "download-images",
	Short: "Download Container Images",
	Long:  `Download Container Images`,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Registry] Downloading container images")

		var wg sync.WaitGroup
		wg.Add(REGISTRY_WORKERS)

		img_chan := make(chan string)

		for w := 0; w < REGISTRY_WORKERS; w++ {
			go DownloadWorker(img_chan, &wg)
		}

		if len(IMAGE_NAME) > 0 {
			// Download single image
			img_chan <- IMAGE_NAME
		} else {
			// Download all images
			images, err := GetImageList()
			if err != nil {
				log.Fatal(err)
			}

			for _, img := range images {
				img_chan <- img
			}
		}

		close(img_chan)

		wg.Wait()
	},
}

var registryHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Get Command History",
	Long:  `Get Command History`,

	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[Registry] Listing command history")

		images := []string{}
		var err error

		if len(IMAGE_NAME) > 0 {
			images = append(images, IMAGE_NAME)
		} else {
			images, err = GetImageList()
			if err != nil {
				log.Fatal(err)
			}
		}

		for _, img := range images {
			log.Printf("[Registry] Image: %s", img)

			tags, err := GetImageTags(img)
			if err != nil {
				log.Error(err)
				continue
			}

			for _, tag := range tags {
				commands, err := GetCommandHistory(img, tag)
				if err != nil {
					log.Error(err)
					continue
				}

				outdir := fmt.Sprintf("%s/%s/%s", REGISTRY_COMMANDS, img, tag)
				os.MkdirAll(outdir, os.ModePerm)

				outfile, err := os.OpenFile(fmt.Sprintf("%s/Dockerfile", outdir), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Error(err)
					continue
				}
				defer outfile.Close()

				datawriter := bufio.NewWriter(outfile)
				for _, cmd := range commands {
					datawriter.WriteString(cmd + "\n")
				}

				datawriter.Flush()
			}
		}
	},
}

var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "Interact with Docker Registry",
	Long:  `Interact with Docker Registry`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			log.Error("the following arguments are required: command")
		}
	},
}

func init() {
	rootCmd.AddCommand(registryCmd)

	registryCmd.AddCommand(registryListImagesCmd)
	registryCmd.AddCommand(registryListTagsCmd)
	registryCmd.AddCommand(registryDownloadImagesCmd)
	registryCmd.AddCommand(registryHistoryCmd)

	registryCmd.PersistentFlags().StringVarP(&REGISTRY_SERVER, "server", "s", "", "Server Address")
	registryCmd.PersistentFlags().StringVarP(&REGISTRY_USER, "user", "u", "", "Username")
	registryCmd.PersistentFlags().StringVarP(&REGISTRY_PASS, "password", "p", "", "Password")
	registryCmd.PersistentFlags().StringVarP(&IMAGE_NAME, "image", "i", "", "Image Name")
	registryCmd.PersistentFlags().StringVarP(&REGISTRY_SERVER_TYPE, "type", "t", "Docker", "Server Type (Docker or Nexus)")

	registryDownloadImagesCmd.PersistentFlags().BoolVarP(&IMAGE_LATEST, "latest", "l", false, "Download only latest version")

	var err error

	if REGISTRY_IMAGES, err = GetConfigParam("registry.images"); err != nil {
		log.Fatal(err)
	}

	if REGISTRY_COMMANDS, err = GetConfigParam("registry.commands"); err != nil {
		log.Fatal(err)
	}

	if REGISTRY_WORKERS, err = GetConfigParamInt("registry.workers"); err != nil {
		log.Fatal(err)
	}
}
