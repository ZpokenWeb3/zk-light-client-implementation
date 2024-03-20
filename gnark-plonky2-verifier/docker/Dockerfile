# syntax=docker/dockerfile:1

FROM golang:1.22-alpine

# Install curl
RUN apk update && apk add --no-cache curl

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/engine/reference/builder/#copy
COPY . ./

ENV USE_BIT_DECOMPOSITION_RANGE_CHECK=true
RUN go run compile_build.go

# Optional:
# To bind to a TCP port, runtime parameters must be supplied to the docker command.
# But we can document in the Dockerfile what ports
# the application is going to listen on by default.
# https://docs.docker.com/engine/reference/builder/#expose
EXPOSE 8010

# Run
ENV USE_BIT_DECOMPOSITION_RANGE_CHECK=true
CMD ["go", "run", "run_api.go"]