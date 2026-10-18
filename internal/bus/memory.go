package bus

import (
	"context"
	"sync"

	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
)

type Memory struct {
	mu       sync.RWMutex
	handlers []Handler
}

func NewMemory() *Memory { return &Memory{} }

func (m *Memory) Publish(ctx context.Context, event domain.Event) error {
	m.mu.RLock()
	handlers := append([]Handler(nil), m.handlers...)
	m.mu.RUnlock()
	for _, handler := range handlers {
		if err := handler(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

func (m *Memory) Subscribe(ctx context.Context, handler Handler) error {
	m.mu.Lock()
	m.handlers = append(m.handlers, handler)
	m.mu.Unlock()
	return nil
}
func (*Memory) Close() error { return nil }
