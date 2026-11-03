package runner

import "github.com/projectdiscovery/gologger"

// Version is the current release version of urloot.
const Version = "v0.1.0"

const banner = `
               __            __ 
  __  _______/ /___  ____  / /_
 / / / / ___/ / __ \/ __ \/ __/
/ /_/ / /  / / /_/ / /_/ / /_  
\__,_/_/  /_/\____/\____/\__/  
`

func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\turloot %s - endpoint & parameter intelligence\n\n", Version)
}
