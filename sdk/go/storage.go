package farcast

import "context"

// StorageAPI provides object storage through DataSphere. Reads and writes
// are encrypted transparently — the application handles plaintext while the
// cloud provider sees only encrypted blobs — and the backing object store
// (S3, GCS, …) is hidden behind the key-addressed interface.
type StorageAPI interface {
	Read(ctx context.Context, key string) ([]byte, error)
	Write(ctx context.Context, key string, data []byte) error
	List(ctx context.Context, prefix string) ([]string, error)
	Delete(ctx context.Context, key string) error
}

// Storage returns the storage capability.
//
// Implementation lands in a later phase; until then this returns a stub
// whose methods yield ErrNotImplemented.
func Storage() StorageAPI {
	return storageStub{}
}

var _ StorageAPI = storageStub{}

type storageStub struct{}

func (storageStub) Read(context.Context, string) ([]byte, error)   { return nil, ErrNotImplemented }
func (storageStub) Write(context.Context, string, []byte) error    { return ErrNotImplemented }
func (storageStub) List(context.Context, string) ([]string, error) { return nil, ErrNotImplemented }
func (storageStub) Delete(context.Context, string) error           { return ErrNotImplemented }
