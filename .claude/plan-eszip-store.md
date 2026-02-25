# Eszip Store Implementation Plan

## Overview

Implement an abstracted storage layer for eszip bundles (and other EdgeFunction assets like .wasm and .so files) with two backends:
- **File-backed store** - For local development and testing
- **S3-backed store** - For production deployments

## Current State

EdgeFunction assets are stored locally at `$baseDir/run/ingest/store/{name}/` with explicit TODOs at `pkg/apiserver/ingest/edgefunction.go:405,634,764` indicating intent to migrate to object store. The current HTTP server (`ListenAndServeEdgeFuncs`) reads directly from the filesystem.

## Proposed Architecture

```
pkg/apiserver/ingest/store/
├── store.go          # Interface + factory
├── file.go           # File-backed implementation
├── s3.go             # S3-backed implementation
└── store_test.go     # Tests
```

## Interface Design

```go
// pkg/apiserver/ingest/store/store.go

package store

import (
    "context"
    "io"
)

// AssetType identifies the type of EdgeFunction asset
type AssetType string

const (
    AssetTypeEszip AssetType = "eszip"  // JavaScript bundle
    AssetTypeWasm  AssetType = "wasm"   // WebAssembly module
    AssetTypeGo    AssetType = "go"     // Go plugin (.so)
)

// Store provides storage operations for EdgeFunction assets
type Store interface {
    // Put stores an asset. The reader is consumed and closed by the implementation.
    Put(ctx context.Context, ref string, assetType AssetType, r io.Reader) error

    // Get retrieves an asset. Caller must close the returned ReadCloser.
    // Returns os.ErrNotExist if not found.
    Get(ctx context.Context, ref string, assetType AssetType) (io.ReadCloser, error)

    // Delete removes an asset.
    Delete(ctx context.Context, ref string, assetType AssetType) error

    // Exists checks if an asset exists.
    Exists(ctx context.Context, ref string, assetType AssetType) (bool, error)
}
```

## File Store Implementation

```go
// pkg/apiserver/ingest/store/file.go

type FileStore struct {
    baseDir string
}

func NewFileStore(baseDir string) (*FileStore, error) {
    // Creates baseDir if it doesn't exist
}

// Key layout: {baseDir}/{ref}/{assetType}
// e.g., /data/store/my-func-rev-abc123/eszip
```

**Key behaviors:**
- Atomic writes using temp file + rename (existing symlink pattern)
- Direct file reads with `os.Open`
- Compatible with existing HTTP serving (can mount same directory)

## S3 Store Implementation

```go
// pkg/apiserver/ingest/store/s3.go

type S3Store struct {
    client *s3.Client
    bucket string
    prefix string  // optional key prefix
}

type S3Config struct {
    Region   string
    Bucket   string
    Prefix   string
    Endpoint string // for MinIO/localstack compatibility
}

func NewS3Store(ctx context.Context, cfg S3Config) (*S3Store, error) {
    // Uses AWS SDK v2 with default credential chain
}

// Key layout: {prefix}/{ref}/{assetType}
// e.g., s3://my-bucket/edgefuncs/my-func-rev-abc123/eszip
```

**Key behaviors:**
- Uses `s3.PutObject` with streaming upload
- Uses `s3.GetObject` returning the response body as ReadCloser
- Supports custom endpoints for MinIO/LocalStack testing

## Configuration

Add to existing config or environment:

```go
// pkg/apiserver/ingest/config.go or similar

type StoreConfig struct {
    // Type selects the store backend: "file" or "s3"
    Type string `json:"type" yaml:"type"`

    // File store options (when Type = "file")
    File struct {
        BaseDir string `json:"baseDir" yaml:"baseDir"`
    } `json:"file" yaml:"file"`

    // S3 store options (when Type = "s3")
    S3 struct {
        Region   string `json:"region" yaml:"region"`
        Bucket   string `json:"bucket" yaml:"bucket"`
        Prefix   string `json:"prefix" yaml:"prefix"`
        Endpoint string `json:"endpoint" yaml:"endpoint"` // optional
    } `json:"s3" yaml:"s3"`
}
```

## Integration Points

### 1. Replace direct filesystem calls in `edgefunction.go`

Current (line ~764):
```go
err = os.Rename(stagingPath, filepath.Join(storeDir, "bin.eszip"))
```

New:
```go
f, err := os.Open(stagingPath)
if err != nil { return err }
defer f.Close()
err = w.store.Put(ctx, name, store.AssetTypeEszip, f)
```

### 2. Update HTTP handler (`ServeHTTP`)

Current:
```go
p := filepath.Join(storeDir(name), filename)
http.ServeFile(wr, req, p)
```

New:
```go
rc, err := w.store.Get(req.Context(), name, assetType)
if err != nil {
    if os.IsNotExist(err) {
        http.NotFound(wr, req)
        return
    }
    http.Error(wr, err.Error(), http.StatusInternalServerError)
    return
}
defer rc.Close()
io.Copy(wr, rc)
```

### 3. Cleanup in workflows

Current:
```go
os.RemoveAll(storeDir(name))
```

New:
```go
w.store.Delete(ctx, name, store.AssetTypeEszip)
// etc for other asset types
```

## Implementation Steps

1. **Create store package with interface** (`pkg/apiserver/ingest/store/store.go`)

2. **Implement FileStore** (`file.go`)
   - Constructor with directory creation
   - Put with atomic write (temp + rename)
   - Get returning os.File
   - Delete and Exists

3. **Implement S3Store** (`s3.go`)
   - Use AWS SDK v2 (`github.com/aws/aws-sdk-go-v2`)
   - Constructor with config loading
   - Put with streaming PutObject
   - Get returning GetObject response body
   - Delete and Exists (HeadObject)

4. **Add factory function** (`store.go`)
   ```go
   func New(cfg StoreConfig) (Store, error)
   ```

5. **Write tests** (`store_test.go`)
   - Unit tests with FileStore
   - Integration test pattern for S3 (LocalStack or skip)

6. **Integrate into worker** (`edgefunction.go`)
   - Add store field to worker struct
   - Update StoreEszipActivity
   - Update StoreWasmActivity
   - Update StoreGoActivity
   - Update ServeHTTP handler

7. **Wire up configuration**
   - Add StoreConfig to worker options
   - Default to FileStore for backwards compatibility

## Testing Strategy

- **FileStore**: Standard unit tests with temp directories
- **S3Store**:
  - Unit tests with mock S3 client interface
  - Optional integration tests with LocalStack (via `endpoint` config)
- **Integration**: Existing EdgeFunction workflow tests should continue to pass

## Dependencies to Add

```
github.com/aws/aws-sdk-go-v2
github.com/aws/aws-sdk-go-v2/config
github.com/aws/aws-sdk-go-v2/service/s3
```

## Backwards Compatibility

- Default store type = "file" with existing baseDir location
- Existing deployments continue to work without config changes
- HTTP serving interface unchanged (backplane compatibility)

## Future Considerations (Out of Scope)

- Signed URL generation for direct S3 downloads (bypass apiserver)
- Cache layer for frequently accessed assets
- Multi-region replication
- Compression/deduplication
