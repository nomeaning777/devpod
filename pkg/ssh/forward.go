package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/loft-sh/log"
	"golang.org/x/crypto/ssh"
)

type ForwardingFunction func(
	net.Conn,
	*ssh.Client,
	string,
	string,
	log.Logger,
)

func PortForward(
	ctx context.Context,
	client *ssh.Client,
	localNetwork, localAddr, remoteNetwork, remoteAddr string,
	exitAfterTimeout time.Duration,
	log log.Logger,
) error {
	listener, err := net.Listen(localNetwork, localAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	return portForwarding(
		ctx, client, listener,
		localNetwork, localAddr, remoteNetwork, remoteAddr,
		exitAfterTimeout, log, forward,
	)
}

func ReversePortForward(
	ctx context.Context,
	client *ssh.Client,
	remoteNetwork, remoteAddr, localNetwork, localAddr string,
	exitAfterTimeout time.Duration,
	log log.Logger,
) error {
	listener, err := client.Listen(remoteNetwork, remoteAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	return portForwarding(
		ctx, client, listener,
		remoteNetwork, remoteAddr, localNetwork, localAddr,
		exitAfterTimeout, log, reverseForward,
	)
}

func portForwarding(
	ctx context.Context,
	client *ssh.Client,
	listener net.Listener,
	srcNetwork, srcAddr, dstNetwork, dstAddr string,
	exitAfterTimeout time.Duration,
	log log.Logger,
	forwardFn ForwardingFunction,
) error {
	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			_ = listener.Close()
		}
	}()

	counter := newConnectionCounter(ctx, exitAfterTimeout, func() {
		log.Fatal("Stopping devpod up, because it stayed idle for a while. You can disable this via 'devpod context set-options -o EXIT_AFTER_TIMEOUT=false'")
	}, srcAddr, log)
	for {
		// waiting for a new connection
		connection, err := listener.Accept()
		if err != nil {
			return err
		}

		// tell the counter there is a connection
		counter.Add()

		// forward connection
		go func() {
			defer counter.Dec()

			forwardFn(connection, client, dstNetwork, dstAddr, log)
		}()
	}
}

func forward(
	localConn net.Conn,
	client *ssh.Client,
	remoteNetwork, remoteAddr string,
	log log.Logger,
) {
	// Setup sshConn (type net.Conn)
	sshConn, err := client.Dial(remoteNetwork, remoteAddr)
	if err != nil {
		log.Debugf("error dialing remote: %v", err)
		return
	}
	defer sshConn.Close()

	// Copy localConn.Reader to sshConn.Writer
	waitGroup := sync.WaitGroup{}
	go func() {
		defer waitGroup.Done()
		defer sshConn.Close()

		_, err = io.Copy(sshConn, localConn)
		if err != nil {
			log.Debugf("error copying to remote: %v", err)
		}
	}()
	waitGroup.Add(1)

	// Copy sshConn.Reader to localConn.Writer
	go func() {
		defer waitGroup.Done()
		defer localConn.Close()

		_, err = io.Copy(localConn, sshConn)
		if err != nil {
			log.Debugf("error copying to local: %v", err)
		}
	}()
	waitGroup.Add(1)
	waitGroup.Wait()
}

func reverseForward(
	remoteConn net.Conn,
	client *ssh.Client,
	localNetwork, localAddr string,
	log log.Logger,
) {
	// Setup localConn (type net.Conn)
	localConn, err := net.Dial(localNetwork, localAddr)
	if err != nil {
		log.Debugf("error dialing remote: %v", err)
		return
	}
	defer localConn.Close()

	// Copy localConn.Reader to sshConn.Writer
	waitGroup := sync.WaitGroup{}
	go func() {
		defer waitGroup.Done()
		defer localConn.Close()

		_, err = io.Copy(localConn, remoteConn)
		if err != nil {
			log.Debugf("error copying to local: %v", err)
		}
	}()
	waitGroup.Add(1)

	// Copy sshConn.Reader to localConn.Writer
	go func() {
		defer waitGroup.Done()
		defer remoteConn.Close()

		_, err = io.Copy(remoteConn, localConn)
		if err != nil {
			log.Debugf("error copying to remote: %v", err)
		}
	}()
	waitGroup.Add(1)
	waitGroup.Wait()
}

func GpgAgentForwardForWindows(
	ctx context.Context,
	client *ssh.Client,
	remoteSocketPath string,
	localSocketPort int,
	localSocketKey []byte,
	exitAfterTimeout time.Duration,
	logger log.Logger,
) error {
	listener, err := client.Listen("unix", remoteSocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()

	return portForwarding(
		ctx, client, listener,
		"unix", remoteSocketPath, "tcp", fmt.Sprintf("127.0.0.1:%d", localSocketPort),
		exitAfterTimeout, logger, func(remoteConn net.Conn,
			client *ssh.Client,
			localNetwork, localAddr string,
			log log.Logger) {
			// Setup localConn (type net.Conn)
			localConn, err := net.Dial(localNetwork, localAddr)
			if err != nil {
				log.Debugf("error dialing remote: %v", err)
				return
			}
			if len(localSocketKey) != 16 {
				log.Errorf("invalid gpg agent key length: %d", len(localSocketKey))
			}
			defer localConn.Close()
			if _, err := localConn.Write(localSocketKey); err != nil {
				log.Errorf("error writing gpg agent key: %v", err)
				return
			}

			// Copy localConn.Reader to sshConn.Writer
			waitGroup := sync.WaitGroup{}
			go func() {
				defer waitGroup.Done()
				defer localConn.Close()

				_, err = io.Copy(localConn, remoteConn)
				if err != nil {
					log.Debugf("error copying to local: %v", err)
				}
			}()
			waitGroup.Add(1)

			// Copy sshConn.Reader to localConn.Writer
			go func() {
				defer waitGroup.Done()
				defer remoteConn.Close()

				_, err = io.Copy(remoteConn, localConn)
				if err != nil {
					log.Debugf("error copying to remote: %v", err)
				}
			}()
			waitGroup.Add(1)
			waitGroup.Wait()
		},
	)
}
