package store

import (
	"context"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
)

type Store interface {
	SaveEvent(context.Context, domain.Event) error
	UpsertAsset(context.Context, domain.Event) error
	UpsertAlert(context.Context, domain.Event, domain.Finding, time.Duration) (domain.Alert, bool, error)
	ListEvents(context.Context, int) ([]domain.Event, error)
	ListAlerts(context.Context, string, int) ([]domain.Alert, error)
	UpdateAlert(context.Context, int64, string, string) error
	ListAssets(context.Context) ([]domain.Asset, error)
	Overview(context.Context) (domain.Overview, error)
	CreateIncident(context.Context, domain.Incident) (domain.Incident, error)
	ListIncidents(context.Context) ([]domain.Incident, error)
	Close() error
}
