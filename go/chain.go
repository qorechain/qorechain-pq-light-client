// SPDX-License-Identifier: Apache-2.0

package pqlightclient

import "context"

// CheckpointSource is where a light client gets checkpoints from. Relayers
// and applications can implement it over any transport; the verifier does not
// depend on it.
type CheckpointSource interface {
	FetchCheckpoint(ctx context.Context, chainID string, epoch uint64) (*SignedCheckpoint, error)
}

// FetchCheckpoint fetches a signed checkpoint from a QoreChain node.
//
// Requires chain support (not scheduled): QoreChain does not produce
// post-quantum checkpoints, so this always returns an *Error with
// CodeRequiresChainSupport and makes no network request.
func FetchCheckpoint(ctx context.Context, endpoint, chainID string, epoch uint64) (*SignedCheckpoint, error) {
	_, _, _, _ = ctx, endpoint, chainID, epoch
	return nil, &Error{Code: CodeRequiresChainSupport, Detail: RequiresChainSupportMessage}
}

// ChainCheckpointSource is a CheckpointSource over FetchCheckpoint; it fails
// until the chain supports checkpoints.
type ChainCheckpointSource struct {
	Endpoint string
}

// FetchCheckpoint implements CheckpointSource.
func (s ChainCheckpointSource) FetchCheckpoint(ctx context.Context, chainID string, epoch uint64) (*SignedCheckpoint, error) {
	return FetchCheckpoint(ctx, s.Endpoint, chainID, epoch)
}
