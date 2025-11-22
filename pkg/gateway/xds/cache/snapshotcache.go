// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// This file contains code derived from Contour,
// https://github.com/projectcontour/contour
// from the source file
// https://github.com/projectcontour/contour/blob/main/internal/xds/v3/snapshotter.go
// and is provided here subject to the following:
// Copyright Project Contour Authors
// SPDX-License-Identifier: Apache-2.0
package cache

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"sync"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoylog "github.com/envoyproxy/go-control-plane/pkg/log"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	xdstypes "github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

var Hash = cachev3.IDHash{}

// SnapshotCacheWithCallbacks uses the go-control-plane SimpleCache to store snapshots of
// Envoy resources, sliced by Node ID so that we can do incremental xDS properly.
// It does this by also implementing callbacks to make sure that the cache is kept
// up to date for each new node.
//
// Having the cache also implement the callbacks is a little bit hacky, but it makes sure
// that all the required bookkeeping happens.
// TODO(youngnick): Talk to the go-control-plane maintainers and see if we can upstream
// this in a better way.
type SnapshotCacheWithCallbacks interface {
	cachev3.SnapshotCache
	serverv3.Callbacks
	GenerateNewSnapshot(string, types.XdsResources) error
}

type snapshotMap map[string]*cachev3.Snapshot

type nodeInfoMap map[int64]*corev3.Node

type nodeBackoff struct {
	backoff     wait.Backoff
	lastAttempt time.Time
}

type backoffMap map[string]*nodeBackoff

type snapshotCache struct {
	cachev3.SnapshotCache
	snapshotVersion int64
	lastSnapshot    snapshotMap

	mu               sync.Mutex
	streamIDNodeInfo nodeInfoMap
	nodeBackoffs     backoffMap
	resources        *message.ProviderResources
}

// NewSnapshotCache gives you a fresh SnapshotCache.
// It needs a logger that supports the go-control-plane
// required interface (Debugf, Infof, Warnf, and Errorf).
func NewSnapshotCache(ads bool, logger *slog.Logger, resources *message.ProviderResources) SnapshotCacheWithCallbacks {
	l := envoylog.LoggerFuncs{
		DebugFunc: func(f string, args ...interface{}) {
			logger.Info(fmt.Sprintf(f, args...))
		},
		InfoFunc: func(f string, args ...interface{}) {
			logger.Info(fmt.Sprintf(f, args...))
		},
		WarnFunc: func(f string, args ...interface{}) {
			logger.Warn(fmt.Sprintf(f, args...))
		},
		ErrorFunc: func(f string, args ...interface{}) {
			logger.Error(fmt.Sprintf(f, args...))
		},
	}
	return &snapshotCache{
		SnapshotCache: cachev3.NewSnapshotCache(ads, &Hash, l),
		lastSnapshot:  make(snapshotMap),

		streamIDNodeInfo: make(nodeInfoMap),
		nodeBackoffs:     make(backoffMap),
		resources:        resources,
	}
}

// newSnapshotVersion increments the current snapshotVersion
// and returns as a string.
func (s *snapshotCache) newSnapshotVersion() string {
	// Reset the snapshotVersion if it ever hits max size.
	if s.snapshotVersion == math.MaxInt64 {
		s.snapshotVersion = 0
	}

	// Increment the snapshot version & return as string.
	s.snapshotVersion++
	return strconv.FormatInt(s.snapshotVersion, 10)
}

// GenerateNewSnapshot takes a table of resources (the output from the IR->xDS
// translator) and updates the snapshot version.
func (s *snapshotCache) GenerateNewSnapshot(irKey string, resources types.XdsResources) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Infof("Generating a new snapshot for ir key: %s", irKey)

	version := s.newSnapshotVersion()

	// Create a snapshot with all xDS resources.
	snapshot, err := cachev3.NewSnapshot(
		version,
		resources,
	)
	if err != nil {
		return err
	}

	s.lastSnapshot[irKey] = snapshot

	for _, node := range s.getNodeIDs(irKey) {
		log.Debugf("Generating a snapshot with Node %s", node)
		err := s.SetSnapshot(context.TODO(), node, snapshot)
		if err != nil {
			return err
		}
	}

	return nil
}

// getNodeIDs retrieves the node ids from the node info map whose
// cluster field matches the ir key
func (s *snapshotCache) getNodeIDs(irKey string) []string {
	var nodeIDs []string
	for _, node := range s.streamIDNodeInfo {
		if node != nil && node.Cluster == irKey {
			nodeIDs = append(nodeIDs, node.Id)
		}
	}

	return nodeIDs
}

// OnStreamOpen and the other OnStream* functions implement the callbacks for the
// state-of-the-world stream types.
func (s *snapshotCache) OnStreamOpen(_ context.Context, streamID int64, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Infof("Stream %d opened", streamID)

	s.streamIDNodeInfo[streamID] = nil

	return nil
}

func (s *snapshotCache) OnStreamClosed(streamID int64, _ *corev3.Node) {
	// TODO: something with the node?
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.streamIDNodeInfo, streamID)
}

func (s *snapshotCache) OnStreamRequest(streamID int64, req *discoveryv3.DiscoveryRequest) error {
	s.mu.Lock()
	// We could do this a little earlier than the defer, since the last half of this func is only logging
	// but that seemed like a premature optimization.
	defer s.mu.Unlock()

	// It's possible that only the first discovery request will have a node ID set.
	// We also need to save the node ID to the node list anyway.
	// So check if we have a nodeID for this stream already, then set it if not.
	if s.streamIDNodeInfo[streamID] == nil {
		if req.Node.Id == "" {
			return fmt.Errorf("couldn't get the node ID from the first discovery request on stream %d", streamID)
		}
		log.Debugf("First discovery request on stream %d, got nodeID %s, nodeCluster %s", streamID, req.Node.Id, req.Node.Cluster)
		s.streamIDNodeInfo[streamID] = req.Node
	}
	nodeID := s.streamIDNodeInfo[streamID].Id
	cluster := s.streamIDNodeInfo[streamID].Cluster

	log.Infof("Stream %d requested resources for node %s in cluster %s", streamID, nodeID, cluster)

	if s.resources != nil {
		meta, err := xdstypes.ExtractFromNode(s.streamIDNodeInfo[streamID])
		if err != nil {
			return err
		}
		log.Infof("Pushing resources for node %s in cluster %s", nodeID, cluster)
		s.resources.EnvoyResources.Nodes.Store(message.NodeKey{ClusterName: cluster, NodeID: nodeID}, meta)
	}

	var (
		nodeVersion  string
		errorCode    int32
		errorMessage string
	)

	// If no snapshot has been generated yet, we can't do anything, so don't mess with this request.
	// go-control-plane will respond with an empty response, then send an update when a snapshot is generated.
	if s.lastSnapshot[cluster] == nil {
		return nil
	}

	_, err := s.GetSnapshot(nodeID)
	if err != nil {
		err = s.SetSnapshot(context.TODO(), nodeID, s.lastSnapshot[cluster])
		if err != nil {
			return err
		}
	}

	if req.Node != nil {
		if bv := req.Node.GetUserAgentBuildVersion(); bv != nil && bv.Version != nil {
			nodeVersion = fmt.Sprintf("v%d.%d.%d", bv.Version.MajorNumber, bv.Version.MinorNumber, bv.Version.Patch)
		}
	}

	log.Debugf("Got a new request, version_info %s, response_nonce %s, nodeID %s, node_version %s", req.VersionInfo, req.ResponseNonce, nodeID, nodeVersion)

	if status := req.ErrorDetail; status != nil {
		// if Envoy rejected the last update log the details here.
		errorCode = status.Code
		errorMessage = status.Message
		log.Warnf("NACK received: code %d, message %s", errorCode, errorMessage)

		if s.nodeBackoffs[nodeID] == nil {
			s.nodeBackoffs[nodeID] = &nodeBackoff{
				backoff: wait.Backoff{
					Duration: time.Second,
					Factor:   2,
					Steps:    5,
					Cap:      30 * time.Second,
				},
			}
		}

		// Check if enough time has passed since last backoff and reset the backoff if so.
		if time.Since(s.nodeBackoffs[nodeID].lastAttempt) > s.nodeBackoffs[nodeID].backoff.Cap {
			s.nodeBackoffs[nodeID].backoff = wait.Backoff{
				Duration: time.Second,
				Factor:   2,
				Steps:    5,
				Cap:      30 * time.Second,
			}
		}

		// Backoff for a bit before retrying.
		s.nodeBackoffs[nodeID].lastAttempt = time.Now()
		delay := s.nodeBackoffs[nodeID].backoff.Step()
		log.Warnf("Backing off for retry after NACK for node %s for %s", nodeID, delay)
		time.Sleep(delay)
	}

	log.Debugf("handling v3 xDS resource request, version_info %s, response_nonce %s, nodeID %s, node_version %s, resource_names %v, type_url %s, errorCode %d, errorMessage %s",
		req.VersionInfo, req.ResponseNonce,
		nodeID, nodeVersion, req.ResourceNames, req.GetTypeUrl(),
		errorCode, errorMessage)

	return nil
}

func (s *snapshotCache) OnStreamResponse(_ context.Context, streamID int64, _ *discoveryv3.DiscoveryRequest, resp *discoveryv3.DiscoveryResponse) {
	// No mutex lock required here because no writing to the cache.
	node := s.streamIDNodeInfo[streamID]
	if node == nil {
		log.Errorf("Tried to send a response to a node we haven't seen yet on stream %d", streamID)
	} else {
		log.Debugf("Sending Response on stream %d to node %s", streamID, node.Id)
	}

	log.Debugf("Stream %d responded with version_info %s, nonce %s, resources %v", streamID, resp.VersionInfo, resp.Nonce, resp.Resources)
}

// OnDeltaStreamOpen and the other OnDeltaStream*/OnStreamDelta* functions implement
// the callbacks for the incremental xDS versions.
// Yes, the different ordering in the name is part of the go-control-plane interface.
func (s *snapshotCache) OnDeltaStreamOpen(_ context.Context, streamID int64, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure that we're adding the streamID to the Node ID list.
	s.streamIDNodeInfo[streamID] = nil

	return nil
}

func (s *snapshotCache) OnDeltaStreamClosed(streamID int64, node *corev3.Node) {
	// TODO: something with the node?
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.resources != nil {
		s.resources.EnvoyResources.Nodes.Delete(message.NodeKey{ClusterName: node.Cluster, NodeID: node.Id})
	}

	log.Infof("Stream %d closed for node %s in cluster %s", streamID, node.Id, node.Cluster)

	delete(s.streamIDNodeInfo, streamID)
}

func (s *snapshotCache) OnStreamDeltaRequest(streamID int64, req *discoveryv3.DeltaDiscoveryRequest) error {
	s.mu.Lock()
	// We could do this a little earlier than with a defer, since the last half of this func is logging
	// but that seemed like a premature optimization.
	defer s.mu.Unlock()

	var nodeVersion string
	var errorCode int32
	var errorMessage string

	// It's possible that only the first incremental discovery request will have a node ID set.
	// We also need to save the node ID to the node list anyway.
	// So check if we have a nodeID for this stream already, then set it if not.
	node := s.streamIDNodeInfo[streamID]
	if node == nil {
		if req.Node.Id == "" {
			return fmt.Errorf("couldn't get the node ID from the first incremental discovery request on stream %d", streamID)
		}
		log.Debugf("First incremental discovery request on stream %d, got nodeID %s", streamID, req.Node.Id)
		s.streamIDNodeInfo[streamID] = req.Node
	}
	nodeID := s.streamIDNodeInfo[streamID].Id
	cluster := s.streamIDNodeInfo[streamID].Cluster

	log.Infof("Stream %d requested resources for node %s in cluster %s", streamID, nodeID, cluster)

	// If no snapshot has been written into the snapshotCache yet, we can't do anything, so don't mess with
	// this request. go-control-plane will respond with an empty response, then send an update when a
	// snapshot is generated.
	if s.lastSnapshot[cluster] == nil {
		return nil
	}

	_, err := s.GetSnapshot(nodeID)
	if err != nil {
		err = s.SetSnapshot(context.TODO(), nodeID, s.lastSnapshot[cluster])
		if err != nil {
			return err
		}
	}

	if req.Node != nil {
		if bv := req.Node.GetUserAgentBuildVersion(); bv != nil && bv.Version != nil {
			nodeVersion = fmt.Sprintf("v%d.%d.%d", bv.Version.MajorNumber, bv.Version.MinorNumber, bv.Version.Patch)
		}
	}

	log.Debugf("Got a new request, response_nonce %s, nodeID %s, node_version %s",
		req.ResponseNonce, nodeID, nodeVersion)
	if status := req.ErrorDetail; status != nil {
		// if Envoy rejected the last update log the details here.
		errorCode = status.Code
		errorMessage = status.Message
		log.Warnf("NACK received: code %d, message %s", errorCode, errorMessage)

		if s.nodeBackoffs[nodeID] == nil {
			s.nodeBackoffs[nodeID] = &nodeBackoff{
				backoff: wait.Backoff{
					Duration: time.Second,
					Factor:   2,
					Steps:    5,
					Cap:      30 * time.Second,
				},
			}
		}

		// Check if enough time has passed since last backoff and reset the backoff if so.
		if time.Since(s.nodeBackoffs[nodeID].lastAttempt) > s.nodeBackoffs[nodeID].backoff.Cap {
			s.nodeBackoffs[nodeID].backoff = wait.Backoff{
				Duration: time.Second,
				Factor:   2,
				Steps:    5,
				Cap:      30 * time.Second,
			}
		}

		// Backoff for a bit before retrying.
		s.nodeBackoffs[nodeID].lastAttempt = time.Now()
		delay := s.nodeBackoffs[nodeID].backoff.Step()
		log.Warnf("Backing off for retry after NACK for node %s", nodeID)
		time.Sleep(delay)
	}
	log.Debugf("handling v3 xDS resource request, response_nonce %s, nodeID %s, node_version %s, resource_names_subscribe %v, resource_names_unsubscribe %v, type_url %s, errorCode %d, errorMessage %s",
		req.ResponseNonce,
		nodeID, nodeVersion,
		req.ResourceNamesSubscribe, req.ResourceNamesUnsubscribe,
		req.GetTypeUrl(),
		errorCode, errorMessage)

	return nil
}

func (s *snapshotCache) OnStreamDeltaResponse(streamID int64, _ *discoveryv3.DeltaDiscoveryRequest, _ *discoveryv3.DeltaDiscoveryResponse) {
	// No mutex lock required here because no writing to the cache.
	node := s.streamIDNodeInfo[streamID]
	if node == nil {
		log.Errorf("Tried to send a response to a node we haven't seen yet on stream %d", streamID)
	} else {
		log.Debugf("Sending Incremental Response on stream %d to node %s", streamID, node.Id)
	}
}

func (s *snapshotCache) OnFetchRequest(_ context.Context, _ *discoveryv3.DiscoveryRequest) error {
	return nil
}

func (s *snapshotCache) OnFetchResponse(_ *discoveryv3.DiscoveryRequest, _ *discoveryv3.DiscoveryResponse) {
}
