//go:build windows

package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/loft-sh/devpod/pkg/agent"
	"github.com/loft-sh/devpod/pkg/gpg"
	devssh "github.com/loft-sh/devpod/pkg/ssh"
	"github.com/loft-sh/log"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// setupGPGAgent will forward a local gpg-agent into the remote container
// this works by using cmd/agent/workspace/setup_gpg
func (cmd *SSHCmd) setupGPGAgent(
	ctx context.Context,
	containerClient *ssh.Client,
	log log.Logger,
) error {
	writer := log.ErrorStreamOnly().Writer(logrus.InfoLevel, false)
	defer writer.Close()

	log.Debugf("gpg: exporting gpg public key from host")

	// Read the user's public keys and ownertrust from GPG.
	// These commands are executed LOCALLY, the output will be imported by the remote gpg
	pubKeyExport, err := gpg.GetHostPubKey()
	if err != nil {
		return fmt.Errorf("export local public keys from GPG: %w", err)
	}

	log.Debugf("gpg: exporting gpg owner trust from host")

	ownerTrustExport, err := gpg.GetHostOwnerTrust()
	if err != nil {
		return fmt.Errorf("export local ownertrust from GPG: %w", err)
	}

	log.Debugf("gpg: detecting gpg-agent socket path on host")
	// Detect local agent extra socket, this will be forwarded to the remote and
	// symlinked in multiple paths
	gpgExtraSocketBytes, err := exec.Command("gpgconf", []string{"--list-dir", "agent-extra-socket"}...).
		Output()
	if err != nil {
		return err
	}

	gpgExtraSocketPath := strings.TrimSpace(string(gpgExtraSocketBytes))
	log.Debugf("gpg: detected gpg-agent socket path %s", gpgExtraSocketPath)

	gitGpgKey, err := exec.Command("git", []string{"config", "user.signingKey"}...).Output()
	if err != nil {
		log.Debugf("gpg: no git signkey detected, skipping")
	}
	log.Debugf("gpg: detected git sign key %s", gitGpgKey)

	gpgExtraSocketContent, err := os.ReadFile(gpgExtraSocketPath)
	if err != nil {
		return fmt.Errorf("read content of gpg-agent-extra-sock: %w", err)
	}
	gpgExtraSocketKey := gpgExtraSocketContent[len(gpgExtraSocketContent)-16:]
	gpgExtraSocketPort, err := strconv.Atoi(strings.TrimSpace(string(gpgExtraSocketContent[:len(gpgExtraSocketContent)-17])))
	if err != nil {
		return fmt.Errorf("parse tcp port from gpg-agent-extra-sock: %w", err)
	}

	log.Debugf("ssh: starting reverse forwarding socket %s", gpgExtraSocketPath)

	go func() {
		err := cmd.reverseForwardPorts(ctx, containerClient, log)
		if err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		err := cmd.reverseGpgForwardForWindows(ctx, containerClient, log, gpgExtraSocketPort, gpgExtraSocketKey)
		if err != nil {
			log.Fatal(err)
		}
	}()

	pubKeyArgument := base64.StdEncoding.EncodeToString(pubKeyExport)
	ownerTrustArgument := base64.StdEncoding.EncodeToString(ownerTrustExport)

	// Now we forward the agent socket to the remote, and setup remote gpg to use it
	// fix eventual permissions and so on
	forwardAgent := []string{
		agent.ContainerDevPodHelperLocation,
	}

	if log.GetLevel() == logrus.DebugLevel {
		forwardAgent = append(forwardAgent, "--debug")
	}

	forwardAgent = append(forwardAgent, []string{
		"agent",
		"workspace",
		"setup-gpg",
		"--publickey",
		pubKeyArgument,
		"--ownertrust",
		ownerTrustArgument,
		"--socketpath",
		"/tmp/gpg-agent.sock",
	}...)

	if len(gitGpgKey) > 0 {
		forwardAgent = append(forwardAgent, "--gitkey")
		forwardAgent = append(forwardAgent, string(gitGpgKey))
	}

	log.Debugf(
		"gpg: start reverse forward of gpg-agent socket %s, keeping connection open",
		gpgExtraSocketPath,
	)

	command := strings.Join(forwardAgent, " ")

	if cmd.User != "" && cmd.User != "root" {
		command = fmt.Sprintf("su -c \"%s\" '%s'", command, cmd.User)
	}

	return devssh.Run(ctx, containerClient, command, nil, writer, writer)
}

func (cmd *SSHCmd) reverseGpgForwardForWindows(
	ctx context.Context,
	containerClient *ssh.Client,
	log log.Logger,
	gpgExtraSocketPort int,
	gpgExtraSocketKey []byte,
) error {
	timeout, err := cmd.forwardTimeout(log)
	if err != nil {
		return fmt.Errorf("parse forward ports timeout: %w", err)
	}

	// start the forwarding
	log.Infof(
		"Reverse forwarding local gpg-agent-extra-socket to remote unix//tmp/gpg-agent.sock",
	)
	err = devssh.GpgAgentForwardForWindows(
		ctx,
		containerClient,
		"/tmp/gpg-agent.sock",
		gpgExtraSocketPort,
		gpgExtraSocketKey,
		timeout,
		log,
	)
	if err != nil {
		return fmt.Errorf("error gpg-agent forwarding: %w", err)
	}
	return nil
}
