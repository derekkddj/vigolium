package mcp

import (
	"fmt"
	"net/http"

	"github.com/vigolium/vigolium/pkg/evidence"
	vhttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// Reply owns one HTTP operation, including its unprojected SSE body when present.
// JSON extraction is a parser concern and never replaces the captured response.
type Reply struct {
	Body     string
	Header   http.Header
	Exchange *evidence.Exchange
}

func (c *Client) PostRawEvidence(body []byte) (*Reply, error) {
	chain, _, err := c.send("POST", c.path, body, "application/json", "application/json, text/event-stream")
	if err != nil {
		return nil, err
	}
	defer chain.Close()
	if chain.Response() == nil {
		return nil, fmt.Errorf("no response")
	}
	return &Reply{Body: chain.BodyString(), Header: chain.Response().Header.Clone(), Exchange: vhttp.CaptureEvidence(chain)}, nil
}

// Select explicitly binds the returned operation to this assertion. Missing
// receipts are not repaired from the seed input or from JSON-RPC body text.
func Select(result *output.ResultEvent, exchange *evidence.Exchange, role evidence.Role, context *modkit.EvidenceCollector) *output.ResultEvent {
	if result == nil {
		return nil
	}
	result.Request, result.Response = "", ""
	result.EvidenceStatus = "missing"
	result.Evidence = context.Evidence()
	result.AdditionalEvidence = context.Entries()
	modkit.SetPrimaryEvidence(result, exchange, role, "Selected MCP operation")
	return result
}

// Proof retains only bounded relevant operations for one producer assertion.
type Proof struct {
	Primary *evidence.Exchange
	Context modkit.EvidenceCollector
	Payload string
}

func NewProof(exchange *evidence.Exchange) *Proof { return &Proof{Primary: exchange} }
func (p *Proof) Control(exchange *evidence.Exchange) {
	if p != nil {
		p.Context.AddExchange(exchange, evidence.RoleControl, "Negative control")
	}
}
func (p *Proof) Confirmation(exchange *evidence.Exchange) {
	if p != nil {
		p.Context.AddExchange(exchange, evidence.RoleConfirmation, "Independent confirmation")
	}
}
func (p *Proof) Observe(exchange *evidence.Exchange) {
	if p != nil {
		p.Context.AddExchange(exchange, evidence.RoleObservation, "Supporting observation")
	}
}
func (p *Proof) Observation(result *output.ResultEvent) *output.ResultEvent {
	return p.apply(result, evidence.RoleObservation)
}
func (p *Proof) Attack(result *output.ResultEvent) *output.ResultEvent {
	return p.apply(result, evidence.RoleAttack)
}
func (p *Proof) apply(result *output.ResultEvent, role evidence.Role) *output.ResultEvent {
	if result == nil {
		return nil
	}
	if p == nil {
		return Select(result, nil, role, nil)
	}
	result.Payload = p.Payload
	return Select(result, p.Primary, role, &p.Context)
}

func (c *Client) CallToolEvidence(id int, name string, args map[string]any) (*ToolsCallResult, string, *evidence.Exchange, error) {
	op, err := c.PostRawEvidence(BuildToolsCallRequest(id, name, args))
	if err != nil {
		return nil, "", nil, err
	}
	res, err := ParseToolsCallResponse(op.Body)
	if res != nil {
		res.Exchange = op.Exchange
	}
	return res, op.Body, op.Exchange, err
}
func (c *Client) ReadResourceEvidence(id int, uri string) (*ResourcesReadResult, string, *evidence.Exchange, error) {
	op, err := c.PostRawEvidence(BuildResourcesReadRequest(id, uri))
	if err != nil {
		return nil, "", nil, err
	}
	res, err := ParseResourcesReadResponse(op.Body)
	if res != nil {
		res.Exchange = op.Exchange
	}
	return res, op.Body, op.Exchange, err
}
func (c *Client) GetPromptEvidence(id int, name string, args map[string]string) (*PromptsGetResult, string, *evidence.Exchange, error) {
	op, err := c.PostRawEvidence(BuildPromptsGetRequest(id, name, args))
	if err != nil {
		return nil, "", nil, err
	}
	res, err := ParsePromptsGetResponse(op.Body)
	if res != nil {
		res.Exchange = op.Exchange
	}
	return res, op.Body, op.Exchange, err
}
func (c *Client) CompletePromptEvidence(id int, name, arg, value string) (*CompleteResult, string, *evidence.Exchange, error) {
	op, err := c.PostRawEvidence(BuildCompletePromptRequest(id, name, arg, value))
	if err != nil {
		return nil, "", nil, err
	}
	res, err := ParseCompleteResponse(op.Body)
	if res != nil {
		res.Exchange = op.Exchange
	}
	return res, op.Body, op.Exchange, err
}
func (c *Client) CompleteResourceEvidence(id int, uri, arg, value string) (*CompleteResult, string, *evidence.Exchange, error) {
	op, err := c.PostRawEvidence(BuildCompleteResourceRequest(id, uri, arg, value))
	if err != nil {
		return nil, "", nil, err
	}
	res, err := ParseCompleteResponse(op.Body)
	if res != nil {
		res.Exchange = op.Exchange
	}
	return res, op.Body, op.Exchange, err
}
