FROM denoland/deno:1.41.2 as builder

WORKDIR /app
COPY . .

RUN deno cache index.ts

FROM denoland/deno:distroless-1.41.2

WORKDIR /app
COPY --from=builder /app .

ENV HOSTS=0.0.0.0
ENTRYPOINT ["deno", "run", "--allow-read=data,public", "--allow-net", "--allow-env", "index.ts"]
