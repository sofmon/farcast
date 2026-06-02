package farcast

import "context"

// AIAPI provides access to AI through AllThing. It is provider-agnostic:
// the application asks for a completion and AllThing routes it to whichever
// provider the operator configured (Gemini, Claude, OpenAI), without the
// application naming a provider or holding a key.
//
// The request and response shapes below are a starting point, refined in
// the AI implementation phase.
type AIAPI interface {
	Chat(ctx context.Context, req ChatRequest) (ChatResponse, error)
	ChatStream(ctx context.Context, req ChatRequest) (Stream, error)
}

// ChatRequest is a single chat completion request.
type ChatRequest struct {
	Model    string
	Messages []Message
}

// Message is one entry in a chat conversation.
type Message struct {
	Role    string
	Content string
}

// ChatResponse is the result of a non-streaming chat completion.
type ChatResponse struct {
	Content string
}

// Stream yields a chat completion incrementally.
type Stream interface {
	// Recv returns the next chunk of the response, or io.EOF when complete.
	Recv() (string, error)
	Close() error
}

// AI returns the AI capability.
//
// Implementation lands in a later phase; until then this returns a stub
// whose methods yield ErrNotImplemented.
func AI() AIAPI {
	return aiStub{}
}

var _ AIAPI = aiStub{}

type aiStub struct{}

func (aiStub) Chat(context.Context, ChatRequest) (ChatResponse, error) {
	return ChatResponse{}, ErrNotImplemented
}

func (aiStub) ChatStream(context.Context, ChatRequest) (Stream, error) {
	return nil, ErrNotImplemented
}
