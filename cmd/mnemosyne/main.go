package main

import (
	"fmt"
	"log"
	"mnemosyne/internal/app"
	"mnemosyne/internal/store"
	"mnemosyne/internal/snapshot"
	"os"
	"path/filepath"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

func getPaths() (dbPath, snapDir string) {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	portableFile := filepath.Join(exeDir, ".portable")

	if _, err := os.Stat(portableFile); err == nil {
		// Portable mode: all data stays in the binary folder
		return filepath.Join(exeDir, "mnemosyne.db"), filepath.Join(exeDir, "snapshots")
	}

	// Normal mode: use user home directory
	home, _ := os.UserHomeDir()
	appDir := filepath.Join(home, ".mnemosyne")
	_ = os.MkdirAll(appDir, 0700)
	return filepath.Join(appDir, "mnemosyne.db"), filepath.Join(appDir, "snapshots")
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "restore":
			handleRestore()
			return
		case "help", "-h", "--help":
			fmt.Println("Mnemosyne - A Personal Memory Palace")
			fmt.Println("\nUsage:")
			fmt.Println("  mnemosyne           Run the TUI")
			fmt.Println("  mnemosyne restore   Restore from a snapshot file")
			return
		}
	}

	// Default: Run TUI
	runTUI()
}

func handleRestore() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: mnemosyne restore <snapshot_file> <new_db_path>")
		os.Exit(1)
	}

	snapFile := os.Args[2]
	newDB := os.Args[3]

	fmt.Print("Enter Master Password: ")
	pass, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Restoring %s to %s...\n", snapFile, newDB)
	if err := snapshot.Restore(newDB, snapFile, pass); err != nil {
		fmt.Printf("Restore failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Restore complete. You can now run mnemosyne with the new database.")
}

func runTUI() {
	// Setup logging
	f, err := tea.LogToFile("debug.log", "mnemosyne")
	if err != nil {
		fmt.Printf("Error setting up log file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	dbPath, snapDir := getPaths()

	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		log.Printf("Error initializing store: %v", err)
		os.Exit(1)
	}
	defer s.Close()

	p := tea.NewProgram(app.NewModel(s, snapDir), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Printf("Error running program: %v", err)
		os.Exit(1)
	}
}
