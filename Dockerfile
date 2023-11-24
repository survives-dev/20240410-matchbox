FROM denoland/deno:1.38.3 as builder

WORKDIR /app
COPY . .

RUN deno cache index.ts

FROM denoland/deno:distroless-1.38.3

WORKDIR /app
COPY --from=builder /app .

ENV HOSTS=0.0.0.0
ENTRYPOINT ["deno", "run", "--allow-read=.env,.env.defaults,.env.example,data,public", "--allow-net", "--allow-env", "index.ts"]
