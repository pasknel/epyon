package cmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var (
	SSL_INSECURE bool
	VERBOSE      bool
	PROXY_SERVER string
	PROXY_USER   string
	PROXY_PASS   string
	SOCKS_SERVER string
)

var rootCmd = &cobra.Command{
	Use:   "epyon",
	Short: "Epyon: DevOps Ecosystem Pwnage",
	Long:  `Epyon: Swiss army knife for pentesting DevOps ecosystems`,

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Hello From Root Command")
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Disable Certificate Validation (Globally)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	rootCmd.PersistentFlags().BoolVarP(&VERBOSE, "verbose", "V", false, "Verbose")
	rootCmd.PersistentFlags().BoolVarP(&SSL_INSECURE, "ssl-insecure", "K", true, "SSL Insecure")
	rootCmd.PersistentFlags().StringVarP(&PROXY_SERVER, "proxy-server", "X", "", "Proxy Server")
	rootCmd.PersistentFlags().StringVarP(&PROXY_USER, "proxy-user", "U", "", "Proxy User")
	rootCmd.PersistentFlags().StringVarP(&PROXY_PASS, "proxy-pass", "P", "", "Proxy Password")
	rootCmd.PersistentFlags().StringVarP(&SOCKS_SERVER, "socks-server", "S", "", "SOCKS5 Server (ip:port)")
}
