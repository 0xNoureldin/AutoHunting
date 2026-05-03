package output

import (
	"bufio"
	"os"
	"sync"
)

type StreamWriter struct {
	ch   chan string
	wg   sync.WaitGroup
	err  error
	once sync.Once
}

func NewStreamWriter(path string, buffer int) (*StreamWriter, error) {
	if buffer <= 0 {
		buffer = 4096
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	sw := &StreamWriter{ch: make(chan string, buffer)}
	sw.wg.Add(1)
	go func() {
		defer sw.wg.Done()
		defer f.Close()

		w := bufio.NewWriterSize(f, 1024*1024)
		defer func() {
			if err := w.Flush(); err != nil && sw.err == nil {
				sw.err = err
			}
		}()

		for line := range sw.ch {
			if _, err := w.WriteString(line + "\n"); err != nil {
				sw.err = err
				return
			}
		}
	}()
	return sw, nil
}

func (sw *StreamWriter) Write(line string) {
	if sw == nil || line == "" {
		return
	}
	sw.ch <- line
}

func (sw *StreamWriter) Close() error {
	if sw == nil {
		return nil
	}
	sw.once.Do(func() {
		close(sw.ch)
		sw.wg.Wait()
	})
	return sw.err
}
