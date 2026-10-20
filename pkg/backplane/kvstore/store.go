package kvstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/buraksezer/olric"
	"github.com/buraksezer/olric/config"
)

const (
	PubSubChannel = "_apoxy_pubsub"

	// leaveTimeout bounds the olric leave; Discovery.Shutdown waits unbounded.
	leaveTimeout = 8 * time.Second
)

type Store struct {
	k8sNamespace     string
	k8sLabelSelector string

	dev bool

	db *olric.Olric

	leaveOnce    sync.Once
	leaveDone    chan struct{}
	leaveErr     error
	leaveTimeout time.Duration
	// shutdown replaces db.Shutdown in tests.
	shutdown func(context.Context) error
}

// New creates a new kvstore instance.
func New(namespace, labelSelector string) *Store {
	return &Store{
		k8sNamespace:     namespace,
		k8sLabelSelector: labelSelector,
		leaveDone:        make(chan struct{}),
		leaveTimeout:     leaveTimeout,
	}
}

// NewDev creates a new kvstore instance for development.
func NewDev() *Store {
	return &Store{
		dev:          true,
		leaveDone:    make(chan struct{}),
		leaveTimeout: leaveTimeout,
	}
}

// Start starts the kvstore. It returns an error if the kvstore fails to start.
// Uses background context created by New() method.
func (s *Store) Start(started chan struct{}) error {
	cfg := config.New("lan")
	if !s.dev {
		cfg.ServiceDiscovery = NewK8sServiceDiscovery(
			s.k8sNamespace,
			s.k8sLabelSelector,
		)
	}
	cfg.Started = func() {
		if started != nil {
			close(started)
		}
	}

	db, err := olric.New(cfg)
	if err != nil {
		return err
	}
	s.db = db

	return s.db.Start()
}

// Stop leaves the cluster and waits for it until ctx is done.
func (s *Store) Stop(ctx context.Context) error {
	select {
	case <-s.Leave():
		return s.LeaveErr()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Leave is shared by every caller: a second olric Shutdown returns before the member has left.
func (s *Store) Leave() <-chan struct{} {
	s.leaveOnce.Do(func() { go s.leave() })
	return s.leaveDone
}

// LeaveErr returns the result of the leave once Leave's channel is closed.
func (s *Store) LeaveErr() error {
	select {
	case <-s.leaveDone:
		return s.leaveErr
	default:
		return errors.New("kv store leave not finished")
	}
}

func (s *Store) leave() {
	defer close(s.leaveDone)
	shutdown := s.shutdown
	if shutdown == nil {
		if s.db == nil {
			s.leaveErr = errors.New("kv store not started")
			return
		}
		shutdown = s.db.Shutdown
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.leaveTimeout)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- shutdown(ctx) }()
	select {
	case s.leaveErr = <-errCh:
	case <-ctx.Done():
		s.leaveErr = fmt.Errorf("olric leave: %w", ctx.Err())
	}
}

// NewDMap creates a new DMap.
func (s *Store) NewDMap(name string) (olric.DMap, error) {
	return s.db.NewEmbeddedClient().NewDMap(name)
}

func (s *Store) NewPubSub() (*olric.PubSub, error) {
	return s.db.NewEmbeddedClient().NewPubSub()
}
