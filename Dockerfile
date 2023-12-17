FROM denoland/deno:1.39.0 as builder

WORKDIR /app
COPY . .

RUN deno cache index.ts

FROM denoland/deno:distroless-1.39.0

WORKDIR /app
COPY --from=builder /app .

ENV HOSTS=0.0.0.0
ENTRYPOINT ["deno", "run", "--allow-read=data,public", "--allow-net", "--allow-env", "index.ts"]
