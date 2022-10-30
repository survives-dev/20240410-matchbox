FROM denoland/deno:1.27.0 as build

WORKDIR /app
COPY . .

RUN deno vendor index.ts

FROM denoland/deno:distroless-1.27.0

WORKDIR /app
COPY --from=build /app /app
CMD ["run", "--allow-read=.", "--allow-net", "--allow-env", "index.ts"]
