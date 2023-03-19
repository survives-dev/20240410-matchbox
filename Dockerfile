FROM denoland/deno:1.31.3 as build

WORKDIR /app
COPY . .

RUN deno vendor index.ts

FROM denoland/deno:distroless-1.31.3

WORKDIR /app
COPY --from=build /app /app

ENV HOSTS=0.0.0.0
CMD ["run", "--allow-read=.", "--allow-net", "--allow-env", "index.ts"]
