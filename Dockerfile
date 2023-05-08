# Tells docker to use the latest Rust official image
FROM rust:latest as builder
ARG PROFILE=release
WORKDIR /app

# Copy the project files from your machine to the container
COPY ./ ./
# Build your application for release, inside the container
RUN set -eux && cargo build --${PROFILE} 

FROM alpine:3.17

LABEL maintainer="zCloak Network"
LABEL description="zCloak Network provides Zero-Knowledge Proof as a Service for public blockchains."

ARG PROFILE=release
WORKDIR /usr/local/bin


COPY --from=builder /app/target/$PROFILE/actix /usr/local/bin


USER root

# Expose the port for accessing the HTTP server within the container
EXPOSE 3000/tcp
# Run the binary built inside the container
CMD ["actix"]


