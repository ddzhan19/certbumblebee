//go:build !windows

package main

import "fmt"

// Außerhalb von Windows gibt es keine Programmoberfläche, die Oberfläche läuft im Browser.
func runNativeUI() int { return 1 }

func showError(title, text string) { fmt.Println(title+":", text) }

func askYesNo(title, text string) bool { return true }
