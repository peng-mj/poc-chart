package interactive

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
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

// HashPrefix8 returns the first 8 characters of a hex hash string,
// or "????????" when the string is empty.
func HashPrefix8(hashStr string) string {
	if hashStr == "" {
		return "????????"
	}
	if len(hashStr) > 8 {
		return hashStr[:8]
	}
	return hashStr
}

// FormatMessage formats a single chat message line.
//
//	direction "i" = incoming (received), "o" = outgoing (sent)
//
// Example:  456bacde [12:13:10][o]>>hello
func FormatMessage(prefix, direction, content string) string {
	ts := time.Now().Format("15:04:05")
	return fmt.Sprintf("%s [%s][%s]>>%s", prefix, ts, direction, content)
}

// isNormalClose returns true for clean WebSocket / TCP disconnects.
func isNormalClose(err error) bool {
	s := err.Error()
	return strings.Contains(s, "closed") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "close frame") ||
		strings.Contains(s, "StatusNormalClosure") ||
		strings.Contains(s, "use of closed")
}

// InteractiveChat runs an interactive chat session over a SecureChannel.
//
// Messages are displayed as:
//
//	<hash8> [HH:MM:SS][i]>>message   (received from peer)
//	<hash8> [HH:MM:SS][o]>>message   (sent by you)
//
// Type a message and press Enter to send. Type /quit to exit.
func InteractiveChat(channel *client.SecureChannel, myIDPrefix, peerIDPrefix string) {
	fmt.Println("\nChat started. Type '/quit' to exit.")

	done := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() { closeOnce.Do(func() { close(done) }) }

	var mu sync.Mutex
	prompt := func() { fmt.Print(">> ") }

	type recvResult struct {
		msg []byte
		err error
	}

	// Receive goroutine — blocks on channel.Recv()
	recvCh := make(chan recvResult, 1)
	go func() {
		for {
			msg, err := channel.Recv()
			select {
			case recvCh <- recvResult{msg, err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	// Stdin goroutine — blocks on scanner.Scan()
	inputCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			select {
			case inputCh <- scanner.Text():
			case <-done:
				return
			}
		}
	}()

	mu.Lock()
	prompt()
	mu.Unlock()

	for {
		select {
		case <-done:
			fmt.Println("\nChat ended.")
			return

		case text := <-inputCh:
			if text == "/quit" {
				closeDone()
				continue
			}
			if text == "" {
				continue
			}
			if err := channel.Send([]byte(text)); err != nil {
				mu.Lock()
				fmt.Printf("\r\033[KSend error: %v\n", err)
				mu.Unlock()
				closeDone()
				continue
			}
			mu.Lock()
			fmt.Printf("\033[A\r\033[K%s\n", FormatMessage(myIDPrefix, "o", text))
			prompt()
			mu.Unlock()

		case result := <-recvCh:
			if result.err != nil {
				mu.Lock()
				if isNormalClose(result.err) {
					fmt.Println("\r\033[KPeer disconnected.")
				} else {
					fmt.Printf("\r\033[KConnection error: %v\n", result.err)
				}
				mu.Unlock()
				closeDone()
				continue
			}
			if len(result.msg) > 0 {
				mu.Lock()
				fmt.Printf("\r\033[K%s\n", FormatMessage(peerIDPrefix, "i", string(result.msg)))
				prompt()
				mu.Unlock()
			}
		}
	}
}
