FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server
# Create uploads directory for volume mount
RUN mkdir -p /app/uploads

FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /app/server .
COPY --from=builder /app/prompts ./prompts
# Copy uploads dir with nonroot ownership (UID 65532)
COPY --from=builder --chown=65532:65532 /app/uploads ./uploads
USER nonroot:nonroot
ENTRYPOINT ["/app/server"]
