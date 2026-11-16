package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/utils"
)

// browserAuthPhaseMaxTurns is the turn budget for the browser auth phase. The
// generic swarm-phase default (agent.max_turns, 32) is too low here: this phase
// drives a real browser — navigate, locate the form, fill it, submit, read the
// result, and often try several login surfaces — so 32 turns can run out before
// a legitimate login completes and the phase fails with "exceeded max turns". A
// larger configured agent.max_turns still wins (see runAuthPhase).
const browserAuthPhaseMaxTurns = 80

// runAuthPhase executes the browser-based authentication phase using agent-browser.
func (s *SwarmRunner) runAuthPhase(ctx context.Context, cfg SwarmConfig, targetURL string, sessionDir string) (string, error) {
	hostname := hostnameFromURL(targetURL)

	extra := map[string]string{
		"TargetURL": targetURL,
		"Hostname":  hostname,
	}
	if cfg.Credentials != "" {
		extra["Credentials"] = cfg.Credentials
	}
	if cfg.BrowserStartURL != "" {
		extra["BrowserStartURL"] = cfg.BrowserStartURL
	}
	if len(cfg.FocusRoutes) > 0 {
		if data, err := json.Marshal(cfg.FocusRoutes); err == nil {
			extra["FocusRoutes"] = string(data)
		}
	}
	if len(cfg.CredentialSets) > 0 {
		if data, err := json.Marshal(cfg.CredentialSets); err == nil {
			extra["CredentialSets"] = string(data)
		}
	}
	if utils.EnvTruthy(spitolas.EnvBrowserHeaded) {
		extra["BrowserHeaded"] = "1"
	}

	// Give the browser auth phase a budget suited to a multi-step login, but
	// never below a larger agent.max_turns an operator configured on purpose.
	maxTurns := browserAuthPhaseMaxTurns
	if s.engine != nil && s.engine.settings != nil {
		if configured := s.engine.settings.Agent.Olium.MaxTurns; configured > maxTurns {
			maxTurns = configured
		}
	}

	opts := Options{
		AgentName:      cfg.AgentName,
		PromptTemplate: SwarmPromptAuth,
		TargetURL:      targetURL,
		Hostname:       hostname,
		Instruction:    cfg.Instruction,
		SessionDir:     sessionDir,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		MaxTurns:       maxTurns,
	}

	agentResult, runErr := s.engine.RunWithExtra(ctx, opts, extra)
	if runErr != nil {
		return "", fmt.Errorf("auth phase agent failed: %w", runErr)
	}

	writePromptToSessionDir(sessionDir, "auth-prompt.md", agentResult.RenderedPrompt)
	if sessionDir != "" && agentResult.RawOutput != "" {
		writeSessionArtifact(filepath.Join(sessionDir, "auth-output.md"), []byte(agentResult.RawOutput))
	}

	authConfigPath := filepath.Join(sessionDir, "auth-config.yaml")
	if _, err := os.Stat(authConfigPath); err == nil {
		return authConfigPath, nil
	}

	return "", nil
}
