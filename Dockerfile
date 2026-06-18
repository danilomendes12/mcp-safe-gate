# syntax=docker/dockerfile:1

# --- build ---
FROM golang:1.25 AS build
WORKDIR /src

# Cache de dependências antes de copiar o resto do código.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /mcpgate ./cmd/mcpgate

# --- runtime ---
FROM gcr.io/distroless/static-debian12
COPY --from=build /mcpgate /mcpgate
ENTRYPOINT ["/mcpgate", "serve"]
