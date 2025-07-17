package cli

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"github.com/bishopfox/sliver/client/command"
	"github.com/bishopfox/sliver/client/console"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// commandCmd creates a command for executing server commands non-interactively
func commandCmd(con *console.SliverClient) *cobra.Command {
	con.IsCLI = true

	makeCommands := command.ServerCommands(con, nil)
	cmd := makeCommands()
	cmd.Use = "command"
	cmd.Short = "Execute server commands non-interactively"
	cmd.Long = `Execute Sliver server commands from the command line without entering the interactive console.

This command allows you to run server-side operations such as:
  - sessions: List active sessions
  - beacons: List active beacons
  - jobs: List active jobs/listeners
  - generate: Generate new implants
  - profiles: Manage implant profiles
  - operators: Manage operators

Examples:
  sliver-client command sessions
  sliver-client command beacons
  sliver-client command jobs
  sliver-client command generate --mtls localhost --save /tmp/implant
  sliver-client command profiles
`

	// Flags - No special flags needed for basic server commands
	commandFlags := pflag.NewFlagSet("command", pflag.ContinueOnError)
	cmd.Flags().AddFlagSet(commandFlags)

	// Pre-runners (console setup, connection, etc)
	cmd.PersistentPreRunE, cmd.PersistentPostRunE = makeServerRunners(cmd, con)

	// Completions
	makeServerCompleters(cmd, con)

	return cmd
}

func makeServerRunners(commandCmd *cobra.Command, con *console.SliverClient) (pre, post func(cmd *cobra.Command, args []string) error) {
	startConsole, closeConsole := consoleRunnerCmd(con, false)

	// The pre-run function connects to the server and sets up a "fake" console,
	// so we can have access to server commands without an interactive session.
	pre = func(_ *cobra.Command, args []string) error {
		return startConsole(commandCmd, args)
	}

	return pre, closeConsole
}

func makeServerCompleters(cmd *cobra.Command, con *console.SliverClient) {
	comps := carapace.Gen(cmd)

	comps.PreRun(func(cmd *cobra.Command, args []string) {
		cmd.PersistentPreRunE(cmd, args)
	})

	// Server commands don't typically need special flag completions like implant commands
	// but we could add them here if needed in the future
}
