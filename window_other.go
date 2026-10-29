//go:build !windows

package main

import "fmt"

func showError(title, text string) { fmt.Println(title+":", text) }

func askYesNo(title, text string) bool { return true }
