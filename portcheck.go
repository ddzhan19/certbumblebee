package main

import (
	"fmt"
	"net"
)

// checkPort80 prüft, ob der eingebaute Webserver Port 80 benutzen kann.
func checkPort80() (bool, string) {
	ln, err := net.Listen("tcp", ":"+httpPort())
	if err != nil {
		return false, fmt.Sprintf("Port %s ist belegt oder gesperrt (%v). Läuft hier schon ein Webserver, bitte „Vorhandener Webserver“ wählen.", httpPort(), simplifyOSError(err))
	}
	_ = ln.Close()
	return true, fmt.Sprintf("Port %s ist frei. Ob er auch aus dem Internet erreichbar ist, zeigt erst die Ausstellung (am besten zuerst mit „Let’s Encrypt Test“).", httpPort())
}
