FROM denoland/deno:1.29.0 as build

WORKDIR /app
COPY . .

RUN deno vendor index.ts

FROM denoland/deno:distroless-1.29.0

WORKDIR /app
COPY --from=build /app /app

ENV HOSTS=0.0.0.0
CMD ["run", "--allow-read=.", "--allow-net", "--allow-env", "index.ts"]
