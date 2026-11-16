package provider

// HasInternalToolLoop reports built-in transports that execute their own tools
// instead of passing tool calls through the engine. Empty request.Tools cannot
// restrict those transports. Keep this classification shared by orchestration
// and engine dispatch guards; new transports with internal tools must join it.
func HasInternalToolLoop(p Provider) bool {
	switch p.Name() {
	case "claude-code", "claude-sdk-bridge":
		return true
	default:
		return false
	}
}
