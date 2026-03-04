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

func getPaths() (dbPath, appDir string, err error) {
	exePath, exeErr := os.Executable()
	if exeErr == nil {
		exeDir := filepath.Dir(exePath)
		portableFile := filepath.Join(exeDir, ".portable")
		if _, statErr := os.Stat(portableFile); statErr == nil {
			// Portable mode: all data stays in the binary folder
			return filepath.Join(exeDir, "mnemosyne.db"), exeDir, nil
		}
	}

	// Normal mode: use user home directory
	home, homeErr := os.UserHomeDir()
	if homeErr != nil {
		return "", "", fmt.Errorf("cannot determine home directory: %w", homeErr)
	}
	appDir = filepath.Join(home, ".mnemosyne")
	if mkErr := os.MkdirAll(appDir, 0700); mkErr != nil {
		return "", "", fmt.Errorf("cannot create app directory: %w", mkErr)
	}
	return filepath.Join(appDir, "mnemosyne.db"), appDir, nil
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
	dbPath, appDir, err := getPaths()
	if err != nil {
		fmt.Printf("Error determining data paths: %v\n", err)
		os.Exit(1)
	}

	// Setup logging inside the app data directory, not cwd
	f, err := tea.LogToFile(filepath.Join(appDir, "debug.log"), "mnemosyne")
	if err != nil {
		fmt.Printf("Error setting up log file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		log.Printf("Error initializing store: %v", err)
		os.Exit(1)
	}
	defer s.Close()

	p := tea.NewProgram(app.NewModel(s, appDir), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Printf("Error running program: %v", err)
		os.Exit(1)
	}
}
