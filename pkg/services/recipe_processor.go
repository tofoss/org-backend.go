package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/genai"
	"tofoss/org-go/pkg/models"
	"tofoss/org-go/pkg/parser"
	"tofoss/org-go/pkg/utils"

	"github.com/google/uuid"
)

type RecipeProcessor struct {
	recipeRepo   *repositories.RecipeRepository
	jobRepo      *repositories.RecipeJobRepository
	noteRepo     *repositories.NoteRepository
	cacheRepo    *repositories.RecipeURLCacheRepository
	extractor    *parser.MainContentExtractor
	aiClient     genai.DeepseekClient
	systemPrompt string
}

func NewRecipeProcessor(
	recipeRepo *repositories.RecipeRepository,
	jobRepo *repositories.RecipeJobRepository,
	noteRepo *repositories.NoteRepository,
	cacheRepo *repositories.RecipeURLCacheRepository,
) (*RecipeProcessor, error) {
	// Load AI prompt from file
	promptPath := filepath.Join("prompts", "recipe_extraction.txt")
	systemPromptBytes, err := os.ReadFile(promptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load recipe extraction prompt: %w", err)
	}

	return &RecipeProcessor{
		recipeRepo:   recipeRepo,
		jobRepo:      jobRepo,
		noteRepo:     noteRepo,
		cacheRepo:    cacheRepo,
		extractor:    parser.NewMainContentExtractor(),
		aiClient:     genai.NewDeepseekClient(),
		systemPrompt: string(systemPromptBytes),
	}, nil
}

// ProcessJob processes a recipe job from URL to completed recipe and note
func (p *RecipeProcessor) ProcessJob(ctx context.Context, job models.RecipeJob) error {
	log.Printf("Processing recipe job %s for URL: %s", job.ID, job.URL)

	// Update job status to processing
	err := p.jobRepo.UpdateStatus(ctx, job.ID, "processing", nil)
	if err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Check URL cache first
	urlHash := p.hashURL(job.URL)
	cached, err := p.cacheRepo.GetByURLHash(ctx, urlHash)
	if err == nil {
		log.Printf("Found cached recipe for URL %s", job.URL)
		return p.createNoteFromCachedRecipe(ctx, job, cached.RecipeID)
	}

	// Extract content from URL
	content, err := p.extractContent(ctx, job.URL)
	if err != nil {
		return p.failJob(ctx, job.ID, fmt.Sprintf("Failed to extract content: %v", err))
	}

	// Process with AI
	recipe, err := p.processWithAI(ctx, content)
	if err != nil {
		return p.failJob(ctx, job.ID, fmt.Sprintf("AI processing failed: %v", err))
	}

	// Set source URL
	recipe.SourceURL = &job.URL

	// Create recipe in database
	now := time.Now()
	recipe.ID = uuid.New()
	recipe.CreatedAt = now
	recipe.UpdatedAt = now

	createdRecipe, err := p.recipeRepo.Create(ctx, recipe)
	if err != nil {
		return p.failJob(ctx, job.ID, fmt.Sprintf("Failed to create recipe: %v", err))
	}

	// Cache the URL -> recipe mapping
	err = p.cacheRepo.Create(ctx, models.RecipeURLCache{
		URLHash:      urlHash,
		OriginalURL:  job.URL,
		RecipeID:     createdRecipe.ID,
		CreatedAt:    now,
		LastAccessed: now,
	})
	if err != nil {
		log.Printf("Warning: failed to cache recipe URL mapping: %v", err)
	}

	// Create note for user
	return p.createNoteFromRecipe(ctx, job, createdRecipe)
}

func (p *RecipeProcessor) extractContent(ctx context.Context, url string) (string, error) {
	// Set timeout for content extraction
	extractCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Use a goroutine to make the extraction cancellable
	contentChan := make(chan string, 1)
	errorChan := make(chan error, 1)

	go func() {
		content, err := p.extractor.ExtractFromURL(url)
		if err != nil {
			errorChan <- err
			return
		}
		contentChan <- content
	}()

	select {
	case content := <-contentChan:
		return content, nil
	case err := <-errorChan:
		return "", err
	case <-extractCtx.Done():
		return "", fmt.Errorf("content extraction timed out")
	}
}

func (p *RecipeProcessor) processWithAI(
	ctx context.Context,
	content string,
) (models.Recipe, error) {
	// Set timeout for AI processing
	aiCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	response, err := p.aiClient.Chat(p.systemPrompt, content, true, aiCtx)
	if err != nil {
		return models.Recipe{}, fmt.Errorf("AI chat failed: %w", err)
	}

	var recipe models.Recipe
	err = json.Unmarshal([]byte(response), &recipe)
	if err != nil {
		return models.Recipe{}, fmt.Errorf("failed to parse AI response: %w", err)
	}

	return recipe, nil
}

func (p *RecipeProcessor) createNoteFromRecipe(
	ctx context.Context,
	job models.RecipeJob,
	recipe models.Recipe,
) error {
	// Generate markdown content
	markdownContent := utils.RecipeToMarkdown(recipe)

	// Create note
	now := time.Now()
	note := models.Note{
		ID:        uuid.New(),
		UserID:    job.UserID,
		Title:     recipe.Name,
		Content:   markdownContent,
		CreatedAt: now,
		UpdatedAt: now,
		Published: false,
	}

	createdNote, err := p.noteRepo.Upsert(ctx, note)
	if err != nil {
		return p.failJob(ctx, job.ID, fmt.Sprintf("Failed to create note: %v", err))
	}

	// Link recipe to note
	err = p.recipeRepo.LinkRecipeToNote(ctx, recipe.ID, createdNote.ID)
	if err != nil {
		return p.failJob(ctx, job.ID, fmt.Sprintf("Failed to link recipe to note: %v", err))
	}

	// Complete the job
	err = p.jobRepo.Complete(ctx, job.ID, recipe.ID, createdNote.ID)
	if err != nil {
		return fmt.Errorf("failed to complete job: %w", err)
	}

	log.Printf("Successfully processed job %s: created recipe %s and note %s",
		job.ID, recipe.ID, createdNote.ID)
	return nil
}

func (p *RecipeProcessor) createNoteFromCachedRecipe(
	ctx context.Context,
	job models.RecipeJob,
	recipeID uuid.UUID,
) error {
	// Fetch the cached recipe
	recipe, err := p.recipeRepo.FetchByID(ctx, recipeID)
	if err != nil {
		return p.failJob(ctx, job.ID, fmt.Sprintf("Failed to fetch cached recipe: %v", err))
	}

	// Update cache access time
	urlHash := p.hashURL(job.URL)
	err = p.cacheRepo.UpdateLastAccessed(ctx, urlHash)
	if err != nil {
		log.Printf("Warning: failed to update cache access time: %v", err)
	}

	return p.createNoteFromRecipe(ctx, job, recipe)
}

func (p *RecipeProcessor) failJob(ctx context.Context, jobID uuid.UUID, errorMessage string) error {
	log.Printf("Job %s failed: %s", jobID, errorMessage)
	err := p.jobRepo.UpdateStatus(ctx, jobID, "failed", &errorMessage)
	if err != nil {
		log.Printf("Failed to update job status to failed: %v", err)
	}
	return fmt.Errorf(errorMessage)
}

func (p *RecipeProcessor) hashURL(url string) string {
	hash := sha256.Sum256([]byte(url))
	return fmt.Sprintf("%x", hash)
}

