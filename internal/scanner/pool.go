package scanner

type WorkerPool struct {
	sem chan struct{}
}

func NewWorkerPool(size int) *WorkerPool {
	if size <= 0 {
		size = 100
	}
	return &WorkerPool{sem: make(chan struct{}, size)}
}

func (p *WorkerPool) Acquire() {
	p.sem <- struct{}{}
}

func (p *WorkerPool) Release() {
	<-p.sem
}
