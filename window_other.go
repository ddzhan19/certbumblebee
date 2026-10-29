//go:build !windows

package main

import "fmt"

// Außerhalb von Windows gibt es kein Programmfenster, die Oberfläche läuft im Browser.
func runWindow(link string, s *server) bool { return false }

func showError(title, text string) { fmt.Println(title+":", text) }

func askYesNo(title, text string) bool { return true }
