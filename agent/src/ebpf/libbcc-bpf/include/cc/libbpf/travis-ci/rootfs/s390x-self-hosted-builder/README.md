# IBM Z self-hosted builder

libbpf CI uses an IBM-provided z15 self-hosted builder. There are no IBM Z
builds of GitHub (GH) Actions runner, and stable qemu-user has problems with .NET
apps, so the builder runs the x86_64 runner version with qemu-user built from
the master branch.

We are currently supporting runners for the following repositories:
* libbpf/libbpf
* kernel-patches/bpf
* kernel-patches/vmtest

Below instructions are directly applicable to libbpf, and require minor
modifications for kernel-patches repos. Currently, qemu-user-static Docker
image is shared between all GitHub runners, but separate actions-runner-\*
service / Docker image is created for each runner type.

## Configuring the builder.

### Install prerequisites.

```
$ sudo apt install -y docker.io  # Ubuntu
```

### Add services.

```
$ sudo cp *.service /etc/systemd/system/
$ sudo systemctl daemon-reload
```

### Create a config file.

```
$ sudo tee /etc/actions-runner-libbpf
repo=<owner>/<name>
access_token=<ghp_***>
```

Access token should have the repo scope, consult
https://docs.github.com/en/rest/reference/actions#create-a-registration-token-for-a-repository
for details.

### Autostart the x86_64 emulation support.

This step is important, you would not be able to build docker container
without having this service running. If container build fails, make sure
service is running properly.

```
$ sudo systemctl enable --now qemu-user-static
```

### Autostart the runner.

```
$ sudo systemctl enable --now actions-runner-libbpf
```

## Rebuilding the image

In order to update the `iiilinuxibmcom/actions-runner-libbpf` image, e.g. to
get the latest OS security fixes, use the following commands:

```
$ sudo docker build \
      --pull \
      -f actions-runner-libbpf.Dockerfile \
      -t iiilinuxibmcom/actions-runner-libbpf \
      .
$ sudo systemctl restart actions-runner-libbpf
```

## Removing persistent data

The `actions-runner-libbpf` service stores various temporary data, such as
runner registration information, work directories and logs, in the
`actions-runner-libbpf` volume. In order to remove it and start from scratch,
e.g. when upgrading the runner or switching it to a different repository, use
the following commands:

```
$ sudo systemctl stop actions-runner-libbpf
$ sudo docker rm -f actions-runner-libbpf
$ sudo docker volume rm actions-runner-libbpf
```

## Troubleshooting

In order to check if service is running, use the following command:

```
$ sudo systemctl status <service name>
```

In order to get logs for service:

```
$ journalctl -u <service name>
```

In order to check which containers are currently active:

```
$ sudo docker ps
```
