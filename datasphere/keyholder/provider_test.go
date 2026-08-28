package keyholder

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sofmon/farcast/datasphere"
)

// memProvider is an in-memory object store. It exists so these tests exercise
// a REAL datasphere.Store — real encryption, real name tokenization — rather
// than a mock of one. Nothing here is FarCast logic; it stands in for the
// cloud.
type memProvider struct {
	mu      sync.Mutex
	objects map[string]datasphere.Object
	// touched records whether the provider was reached at all, so a test can
	// assert that a refusal happened BEFORE any cloud call.
	touched bool
}

func newMemProvider() *memProvider {
	return &memProvider{objects: map[string]datasphere.Object{}}
}

func (m *memProvider) Name() string { return "mem" }

func (m *memProvider) Validate(context.Context, datasphere.BucketRef) error { return nil }

func (m *memProvider) EnsureBucket(_ context.Context, spec datasphere.BucketSpec) (*datasphere.Bucket, error) {
	return &datasphere.Bucket{Ref: datasphere.BucketRef{Name: spec.Name}}, nil
}

func (m *memProvider) DeleteBucket(context.Context, datasphere.BucketRef) error { return nil }

func (m *memProvider) Put(_ context.Context, _ string, obj datasphere.Object) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touched = true
	stored := datasphere.Object{Name: obj.Name, Data: append([]byte(nil), obj.Data...), Meta: obj.Meta}
	m.objects[obj.Name] = stored
	return nil
}

func (m *memProvider) Get(_ context.Context, _, name string) (*datasphere.Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touched = true
	obj, ok := m.objects[name]
	if !ok {
		return nil, datasphere.ErrObjectNotFound
	}
	out := datasphere.Object{Name: obj.Name, Data: append([]byte(nil), obj.Data...), Meta: obj.Meta}
	return &out, nil
}

func (m *memProvider) List(_ context.Context, _, prefix string) ([]datasphere.ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touched = true
	var out []datasphere.ObjectInfo
	for name, obj := range m.objects {
		if strings.HasPrefix(name, prefix) {
			out = append(out, datasphere.ObjectInfo{
				Name: name, Size: int64(len(obj.Data)), Created: time.Unix(0, 0).UTC(), Meta: obj.Meta,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *memProvider) Delete(_ context.Context, _, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touched = true
	delete(m.objects, name)
	return nil
}

func (m *memProvider) PutStream(ctx context.Context, bucket string, obj datasphere.StreamObject) error {
	data, err := io.ReadAll(obj.Data)
	if err != nil {
		return err
	}
	return m.Put(ctx, bucket, datasphere.Object{Name: obj.Name, Data: data, Meta: obj.Meta})
}

func (m *memProvider) GetStream(ctx context.Context, bucket, name string, offset, length int64) (io.ReadCloser, error) {
	obj, err := m.Get(ctx, bucket, name)
	if err != nil {
		return nil, err
	}
	data := obj.Data
	if offset > int64(len(data)) {
		return nil, fmt.Errorf("offset beyond object")
	}
	data = data[offset:]
	if length >= 0 && length < int64(len(data)) {
		data = data[:length]
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *memProvider) wasTouched() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.touched
}

func (m *memProvider) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touched = false
}
