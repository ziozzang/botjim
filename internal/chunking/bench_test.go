package chunking

import "testing"

func BenchmarkChunkSHA4M(b *testing.B) {
	data := make([]byte, 4<<20)
	for i := range data {
		data[i] = byte(i)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ChunkSHA("some/path/file.bin", int64(i), data)
	}
}

func BenchmarkAllZero4M(b *testing.B) {
	data := make([]byte, 4<<20)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_ = AllZero(data)
	}
}
