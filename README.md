
<div align="right">
  <details>
    <summary >🌐 Language</summary>
    <div>
      <div align="center">
        <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=en">English</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=zh-CN">简体中文</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=zh-TW">繁體中文</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=ja">日本語</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=ko">한국어</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=hi">हिन्दी</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=th">ไทย</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=fr">Français</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=de">Deutsch</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=es">Español</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=it">Italiano</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=ru">Русский</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=pt">Português</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=nl">Nederlands</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=pl">Polski</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=ar">العربية</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=fa">فارسی</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=tr">Türkçe</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=vi">Tiếng Việt</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=id">Bahasa Indonesia</a>
        | <a href="https://openaitx.github.io/view.html?user=pasknel&project=epyon&lang=as">অসমীয়া</
      </div>
    </div>
  </details>
</div>

# Epyon

Epyon is a swiss army knife tool for pentesting DevOps ecosystems.

Available modules:

1. Gitlab
2. Github
3. Jenkins
4. Azure DevOps
5. Sonatype Nexus
6. Docker Registry
7. Sonarqube
8. Gitea
9. Artifactory
10. Terraform Cloud/Enterprise
11. Harbor

# Build

Clone the repository and build the project with Golang:

```
$ git clone https://github.com/pasknel/epyon.git
$ cd epyon
$ go build
```

Make sure the "config.yaml" file is in the same folder as the main binary (use "config-example.yaml" as template).

Check the binary:

```
$ ./epyon -h

Epyon: Swiss army knife for pentesting DevOps ecosystems

Usage:
  epyon [flags]
  epyon [command]

Available Commands:
  artifactory Interact with JFrog Artifactory
  azure       Interact with Azure DevOps
  completion  Generate the autocompletion script for the specified shell
  gitea       Interact with Gitea server
  github      Interact with Github (Enterprise and Actions)
  gitlab      Interact with Gitlab Server
  gitleaks    Scan projects folders with Gitleaks
  harbor      Interact with Harbor Server
  help        Help about any command
  horusec     Static source code analysis with Horusec
  jenkins     Interact with Jenkins Server
  nexus       Interact with Nexus Repository
  registry    Interact with Docker Registry
  sonarqube   Interact with Sonarqube API
  terraform   Interact with Terraform Cloud/Enterprise
  trufflehog  Find leaked credentials with TruffleHog

Flags:
  -h, --help                  help for epyon
  -P, --proxy-pass string     Proxy Password
  -X, --proxy-server string   Proxy Server
  -U, --proxy-user string     Proxy User
  -S, --socks-server string   SOCKS5 Server (ip:port)
  -K, --ssl-insecure          SSL Insecure (default true)
  -V, --verbose               Verbose

Use "epyon [command] --help" for more information about a command.
```

# Examples

See the project's wiki for documentation and usage examples

# To do

[Check the TODO file](TODO.md)
