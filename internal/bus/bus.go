package bus

import (
	"context"

	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
)

type Handler func(context.Context, domain.Event) error

type Bus interface {
	Publish(context.Context, domain.Event) error
	Subscribe(context.Context, Handler) error
	Close() error
}
