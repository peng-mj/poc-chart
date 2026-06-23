package interactive

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/mj/pqc-chart-tool/pkg/client"
	"golang.org/x/term"
)

// ReadPassword reads a password from stdin.
func ReadPassword(prompt string) string {
	fmt.Print(prompt)
	
	if term.IsTerminal(int(os.Stdin.Fd())) {
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		return string(password)
	}
	
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(1)
	}
	return strings.TrimSpace(password)
}

// InteractiveChat runs an interactive chat session.
func InteractiveChat(channel *client.SecureChannel) {
	fmt.Println("\nChat started. Type '/quit' to exit.")

	done := make(chan struct{})

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text == "/quit" {
				close(done)
				break
			}
			if text == "" {
				continue
			}
			if err := channel.Send([]byte(text)); err != nil {
				fmt.Printf("Send error: %v\n", err)
				break
			}
		}
	}()

	for {
		select {
		case <-done:
			fmt.Println("\nChat ended.")
			return
		case <-time.After(100 * time.Millisecond):
		}

		msg, err := channel.Recv()
		if err != nil {
			if !strings.Contains(err.Error(), "closed") {
				fmt.Printf("Receive error: %v\n", err)
			}
			return
		}
		if len(msg) > 0 {
			slog.Info("message received", "content", string(msg))
			fmt.Printf("\rPeer: %s\nYou: ", string(msg))
		}
	}
}