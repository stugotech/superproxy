package syncex

import (
	"sync"
)

// WorkerPool deals with coordinating shutdown events.
type WorkerPool interface {
	Close()
	WaitForClose()
	HandleClose(handler func())
	WaitWorkers()
	BeginWork(worker func(), closeHandler func())
}

// workerPool is an implementation of WorkerPool.
type workerPool struct {
	mutex      *sync.Mutex
	stopChan   chan struct{}
	stopped    bool
	workers    int
	workerChan chan int
}

// NewWorkerPool creates a new instance of CloseHandler.
func NewWorkerPool() WorkerPool {
	c := &workerPool{
		mutex:      &sync.Mutex{},
		stopChan:   make(chan struct{}),
		workerChan: make(chan int),
	}
	return c
}

// Close
func (c *workerPool) Close() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !c.stopped {
		close(c.stopChan)
	}
}

// WaitForClose
func (c *workerPool) WaitForClose() {
	<-c.stopChan
}

// HandleClose
func (c *workerPool) HandleClose(handler func()) {
	go (func() {
		c.WaitForClose()
		handler()
	})()
}

// BeginWork adds a worker.
func (c *workerPool) BeginWork(worker func(), closeHandler func()) {
	if closeHandler != nil {
		c.HandleClose(closeHandler)
	}
	go (func() {
		c.workerChan <- 1
		defer (func() { c.workerChan <- -1 })()
		worker()
		c.Close()
	})()
}

// WaitWorkers waits until at least one worker starts and then all workers finish.
func (c *workerPool) WaitWorkers() {
	for {
		i := <-c.workerChan
		c.workers += i
		if c.workers == 0 {
			return
		}
	}
}
