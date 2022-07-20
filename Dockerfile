FROM denoland/deno:1.23.4 as build

WORKDIR /app
COPY . .

RUN deno vendor index.ts

FROM denoland/deno:distroless-1.23.4

WORKDIR /app
COPY --from=build /app /app
CMD ["run", "--allow-read=/app", "--allow-net", "--allow-env", "--import-map=vendor/import_map.json", "index.ts"]
