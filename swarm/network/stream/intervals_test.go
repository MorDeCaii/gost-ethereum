// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package stream

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"gostBlockchain/log"
	"gostBlockchain/node"
	"gostBlockchain/p2p/enode"
	"gostBlockchain/p2p/simulations/adapters"
	"gostBlockchain/swarm/network"
	"gostBlockchain/swarm/network/simulation"
	"gostBlockchain/swarm/state"
	"gostBlockchain/swarm/storage"
	"gostBlockchain/swarm/testutil"
)

func TestIntervalsLive(t *testing.T) {
	testIntervals(t, true, nil, false)
	testIntervals(t, true, nil, true)
}

func TestIntervalsHistory(t *testing.T) {
	testIntervals(t, false, NewRange(9, 26), false)
	testIntervals(t, false, NewRange(9, 26), true)
}

func TestIntervalsLiveAndHistory(t *testing.T) {
	testIntervals(t, true, NewRange(9, 26), false)
	testIntervals(t, true, NewRange(9, 26), true)
}

func testIntervals(t *testing.T, live bool, history *Range, skipCheck bool) {

	t.Skip("temporarily disabled as simulations.WaitTillHealthy cannot be trusted")
	nodes := 2
	chunkCount := dataChunkCount
	externalStreamName := "externalStream"
	externalStreamSessionAt := uint64(50)
	externalStreamMaxKeys := uint64(100)

	sim := simulation.New(map[string]simulation.ServiceFunc{
		"intervalsStreamer": func(ctx *adapters.ServiceContext, bucket *sync.Map) (s node.Service, cleanup func(), err error) {
			n := ctx.Config.Node()
			addr := network.NewAddr(n)
			store, datadir, err := createTestLocalStorageForID(n.ID(), addr)
			if err != nil {
				return nil, nil, err
			}
			bucket.Store(bucketKeyStore, store)
			cleanup = func() {
				store.Close()
				os.RemoveAll(datadir)
			}
			localStore := store.(*storage.LocalStore)
			netStore, err := storage.NewNetStore(localStore, nil)
			if err != nil {
				return nil, nil, err
			}
			kad := network.NewKademlia(addr.Over(), network.NewKadParams())
			delivery := NewDelivery(kad, netStore)
			netStore.NewNetFetcherFunc = network.NewFetcherFactory(delivery.RequestFromPeers, true).New

			r := NewRegistry(addr.ID(), delivery, netStore, state.NewInmemoryStore(), &RegistryOptions{
				Retrieval: RetrievalDisabled,
				Syncing:   SyncingRegisterOnly,
				SkipCheck: skipCheck,
			}, nil)
			bucket.Store(bucketKeyRegistry, r)

			r.RegisterClientFunc(externalStreamName, func(p *Peer, t string, live bool) (Client, error) {
				return newTestExternalClient(netStore), nil
			})
			r.RegisterServerFunc(externalStreamName, func(p *Peer, t string, live bool) (Server, error) {
				return newTestExternalServer(t, externalStreamSessionAt, externalStreamMaxKeys, nil), nil
			})

			fileStore := storage.NewFileStore(localStore, storage.NewFileStoreParams())
			bucket.Store(bucketKeyFileStore, fileStore)

			return r, cleanup, nil

		},
	})
	defer sim.Close()

	log.Info("Adding nodes to simulation")
	_, err := sim.AddNodesAndConnectChain(nodes)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if _, err := sim.WaitTillHealthy(ctx, 2); err != nil {
		t.Fatal(err)
	}

	result := sim.Run(ctx, func(ctx context.Context, sim *simulation.Simulation) error {
		nodeIDs := sim.UpNodeIDs()
		storer := nodeIDs[0]
		checker := nodeIDs[1]

		item, ok := sim.NodeItem(storer, bucketKeyFileStore)
		if !ok {
			return fmt.Errorf("No filestore")
		}
		fileStore := item.(*storage.FileStore)

		size := chunkCount * chunkSize

		_, wait, err := fileStore.Store(ctx, testutil.RandomReader(1, size), int64(size), false)
		if err != nil {
			log.Error("Store error: %v", "err", err)
			t.Fatal(err)
		}
		err = wait(ctx)
		if err != nil {
			log.Error("Wait error: %v", "err", err)
			t.Fatal(err)
		}

		item, ok = sim.NodeItem(checker, bucketKeyRegistry)
		if !ok {
			return fmt.Errorf("No registry")
		}
		registry := item.(*Registry)

		liveErrC := make(chan error)
		historyErrC := make(chan error)

		log.Debug("Watching for disconnections")
		disconnections := sim.PeerEvents(
			context.Background(),
			sim.NodeIDs(),
			simulation.NewPeerEventsFilter().Drop(),
		)

		err = registry.Subscribe(storer, NewStream(externalStreamName, "", live), history, Top)
		if err != nil {
			return err
		}

		go func() {
			for d := range disconnections {
				if d.Error != nil {
					log.Error("peer drop", "node", d.NodeID, "peer", d.PeerID)
					t.Fatal(d.Error)
				}
			}
		}()

		go func() {
			if !live {
				close(liveErrC)
				return
			}

			var err error
			defer func() {
				liveErrC <- err
			}()

			// live stream
			var liveHashesChan chan []byte
			liveHashesChan, err = getHashes(ctx, registry, storer, NewStream(externalStreamName, "", true))
			if err != nil {
				log.Error("get hashes", "err", err)
				return
			}
			i := externalStreamSessionAt

			// we have subscribed, enable notifications
			err = enableNotifications(registry, storer, NewStream(externalStreamName, "", true))
			if err != nil {
				return
			}

			for {
				select {
				case hash := <-liveHashesChan:
					h := binary.BigEndian.Uint64(hash)
					if h != i {
						err = fmt.Errorf("expected live hash %d, got %d", i, h)
						return
					}
					i++
					if i > externalStreamMaxKeys {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		go func() {
			if live && history == nil {
				close(historyErrC)
				return
			}

			var err error
			defer func() {
				historyErrC <- err
			}()

			// history stream
			var historyHashesChan chan []byte
			historyHashesChan, err = getHashes(ctx, registry, storer, NewStream(externalStreamName, "", false))
			if err != nil {
				log.Error("get hashes", "err", err)
				return
			}

			var i uint64
			historyTo := externalStreamMaxKeys
			if history != nil {
				i = history.From
				if history.To != 0 {
					historyTo = history.To
				}
			}

			// we have subscribed, enable notifications
			err = enableNotifications(registry, storer, NewStream(externalStreamName, "", false))
			if err != nil {
				return
			}

			for {
				select {
				case hash := <-historyHashesChan:
					h := binary.BigEndian.Uint64(hash)
					if h != i {
						err = fmt.Errorf("expected history hash %d, got %d", i, h)
						return
					}
					i++
					if i > historyTo {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		if err := <-liveErrC; err != nil {
			return err
		}
		if err := <-historyErrC; err != nil {
			return err
		}

		return nil
	})

	if result.Error != nil {
		t.Fatal(result.Error)
	}
}

func getHashes(ctx context.Context, r *Registry, peerID enode.ID, s Stream) (chan []byte, error) {
	peer := r.getPeer(peerID)

	client, err := peer.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	c := client.Client.(*testExternalClient)

	return c.hashes, nil
}

func enableNotifications(r *Registry, peerID enode.ID, s Stream) error {
	peer := r.getPeer(peerID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := peer.getClient(ctx, s)
	if err != nil {
		return err
	}

	close(client.Client.(*testExternalClient).enableNotificationsC)

	return nil
}

type testExternalClient struct {
	hashes               chan []byte
	store                storage.SyncChunkStore
	enableNotificationsC chan struct{}
}

func newTestExternalClient(store storage.SyncChunkStore) *testExternalClient {
	return &testExternalClient{
		hashes:               make(chan []byte),
		store:                store,
		enableNotificationsC: make(chan struct{}),
	}
}

func (c *testExternalClient) NeedData(ctx context.Context, hash []byte) func(context.Context) error {
	wait := c.store.FetchFunc(ctx, storage.Address(hash))
	if wait == nil {
		return nil
	}
	select {
	case c.hashes <- hash:
	case <-ctx.Done():
		log.Warn("testExternalClient NeedData context", "err", ctx.Err())
		return func(_ context.Context) error {
			return ctx.Err()
		}
	}
	return wait
}

func (c *testExternalClient) BatchDone(Stream, uint64, []byte, []byte) func() (*TakeoverProof, error) {
	return nil
}

func (c *testExternalClient) Close() {}

type testExternalServer struct {
	t         string
	keyFunc   func(key []byte, index uint64)
	sessionAt uint64
	maxKeys   uint64
}

func newTestExternalServer(t string, sessionAt, maxKeys uint64, keyFunc func(key []byte, index uint64)) *testExternalServer {
	if keyFunc == nil {
		keyFunc = binary.BigEndian.PutUint64
	}
	return &testExternalServer{
		t:         t,
		keyFunc:   keyFunc,
		sessionAt: sessionAt,
		maxKeys:   maxKeys,
	}
}

func (s *testExternalServer) SessionIndex() (uint64, error) {
	return s.sessionAt, nil
}

func (s *testExternalServer) SetNextBatch(from uint64, to uint64) ([]byte, uint64, uint64, *HandoverProof, error) {
	if to > s.maxKeys {
		to = s.maxKeys
	}
	b := make([]byte, HashSize*(to-from+1))
	for i := from; i <= to; i++ {
		s.keyFunc(b[(i-from)*HashSize:(i-from+1)*HashSize], i)
	}
	return b, from, to, nil, nil
}

func (s *testExternalServer) GetData(context.Context, []byte) ([]byte, error) {
	return make([]byte, 4096), nil
}

func (s *testExternalServer) Close() {}
