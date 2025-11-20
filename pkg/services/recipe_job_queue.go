package services

import (
	"context"
	"log"
	"sync"
	"time"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/models"
)

type RecipeJobQueue struct {
	jobRepo   *repositories.RecipeJobRepository
	processor *RecipeProcessor
	running   bool
	stopCh    chan struct{}
	wg        sync.WaitGroup

	// Configuration
	pollInterval time.Duration
	batchSize    int
	maxRetries   int
	jobTimeout   time.Duration
}

func NewRecipeJobQueue(
	jobRepo *repositories.RecipeJobRepository,
	processor *RecipeProcessor,
	pollInterval time.Duration,
	batchSize int,
	maxRetries int,
	jobTimeout time.Duration,
) *RecipeJobQueue {
	return &RecipeJobQueue{
		jobRepo:      jobRepo,
		processor:    processor,
		running:      false,
		stopCh:       make(chan struct{}),
		pollInterval: pollInterval,
		batchSize:    batchSize,
		maxRetries:   maxRetries,
		jobTimeout:   jobTimeout,
	}
}

// Start begins the background job processing
func (q *RecipeJobQueue) Start(ctx context.Context) {
	if q.running {
		log.Printf("Recipe job queue is already running")
		return
	}

	q.running = true
	log.Printf("Starting recipe job queue with poll interval: %v", q.pollInterval)

	q.wg.Add(1)
	go q.worker(ctx)
}

// Stop gracefully stops the background job processing
func (q *RecipeJobQueue) Stop() {
	if !q.running {
		return
	}

	log.Printf("Stopping recipe job queue...")
	q.running = false
	close(q.stopCh)
	q.wg.Wait()
	log.Printf("Recipe job queue stopped")
}

// worker is the background goroutine that processes jobs
func (q *RecipeJobQueue) worker(ctx context.Context) {
	defer q.wg.Done()
	
	ticker := time.NewTicker(q.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Recipe job queue worker stopping due to context cancellation")
			return
		case <-q.stopCh:
			log.Printf("Recipe job queue worker stopping due to stop signal")
			return
		case <-ticker.C:
			q.processBatch(ctx)
		}
	}
}

// processBatch fetches and processes a batch of pending jobs
func (q *RecipeJobQueue) processBatch(ctx context.Context) {
	// Fetch pending jobs
	jobs, err := q.jobRepo.FetchPendingJobs(ctx, q.batchSize)
	if err != nil {
		log.Printf("Error fetching pending jobs: %v", err)
		return
	}

	if len(jobs) == 0 {
		// No jobs to process
		return
	}

	log.Printf("Processing batch of %d recipe jobs", len(jobs))

	// Process jobs concurrently
	var wg sync.WaitGroup
	for _, job := range jobs {
		wg.Add(1)
		go func(j models.RecipeJob) {
			defer wg.Done()
			q.processJob(ctx, j)
		}(job)
	}

	wg.Wait()
	log.Printf("Completed processing batch of %d recipe jobs", len(jobs))
}

// processJob handles a single job with retry logic
func (q *RecipeJobQueue) processJob(ctx context.Context, job models.RecipeJob) {
	log.Printf("Processing recipe job %s (attempt %d)", job.ID, q.getJobAttempts(job))

	// Create a context with timeout for this job
	jobCtx, cancel := context.WithTimeout(ctx, q.jobTimeout)
	defer cancel()

	// Process the job
	err := q.processor.ProcessJob(jobCtx, job)
	if err != nil {
		log.Printf("Job %s failed: %v", job.ID, err)
		
		// Check if we should retry
		attempts := q.getJobAttempts(job)
		if attempts < q.maxRetries {
			log.Printf("Job %s will be retried (attempt %d/%d)", job.ID, attempts+1, q.maxRetries)
			// Job stays in "pending" status for retry
			// In a more sophisticated implementation, we could add exponential backoff
			return
		} else {
			log.Printf("Job %s exceeded max retries, marking as failed", job.ID)
			// The processor should have already marked it as failed
		}
	} else {
		log.Printf("Job %s completed successfully", job.ID)
	}
}

// getJobAttempts calculates how many times a job has been attempted
// This is a simple implementation - in production you might want to track this explicitly
func (q *RecipeJobQueue) getJobAttempts(job models.RecipeJob) int {
	// For now, we'll use the age of the job as a proxy for attempts
	// This is a simplification - ideally we'd track attempts explicitly in the database
	age := time.Since(job.CreatedAt)
	
	// Estimate attempts based on age and poll interval
	// This is rough but works for our simple retry logic
	attempts := int(age / q.pollInterval)
	if attempts > q.maxRetries {
		return q.maxRetries + 1 // Cap it to prevent infinite retries
	}
	
	return attempts
}

// GetQueueStats returns information about the current queue state
func (q *RecipeJobQueue) GetQueueStats(ctx context.Context) (QueueStats, error) {
	// This would require additional queries to get comprehensive stats
	// For now, just return basic info
	return QueueStats{
		Running:      q.running,
		PollInterval: q.pollInterval,
		BatchSize:    q.batchSize,
		MaxRetries:   q.maxRetries,
	}, nil
}

type QueueStats struct {
	Running      bool          `json:"running"`
	PollInterval time.Duration `json:"pollInterval"`
	BatchSize    int           `json:"batchSize"`
	MaxRetries   int           `json:"maxRetries"`
}