package bus

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
	"github.com/nats-io/nats.go"
)

type NATS struct {
	conn    *nats.Conn
	subject string
	queue   string
}

func NewNATS(url, subject, queue string) (*NATS, error) {
	conn, err := nats.Connect(url, nats.Name("go-ditecting"), nats.Timeout(5*time.Second), nats.MaxReconnects(-1), nats.ReconnectWait(time.Second))
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}
	return &NATS{conn: conn, subject: subject, queue: queue}, nil
}

func (n *NATS) Publish(_ context.Context, event domain.Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if err := n.conn.Publish(n.subject, payload); err != nil {
		return fmt.Errorf("publish event: %w", err)
	}
	return n.conn.Flush()
}

func (n *NATS) Subscribe(ctx context.Context, handler Handler) error {
	callback := func(message *nats.Msg) {
		var event domain.Event
		if err := json.Unmarshal(message.Data, &event); err != nil {
			return
		}
		_ = handler(ctx, event)
	}
	var err error
	if n.queue == "" {
		_, err = n.conn.Subscribe(n.subject, callback)
	} else {
		_, err = n.conn.QueueSubscribe(n.subject, n.queue, callback)
	}
	if err != nil {
		return fmt.Errorf("subscribe events: %w", err)
	}
	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("flush subscription: %w", err)
	}
	return nil
}

func (n *NATS) Close() error { n.conn.Drain(); n.conn.Close(); return nil }
