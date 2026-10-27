FROM node:22-alpine AS build
WORKDIR /app
COPY src ./src
RUN npm install --no-audit --no-fund typescript@5.9.3 @types/node@22.15.0 \
 && npx tsc --module NodeNext --moduleResolution NodeNext --target ES2022 --strict --types node --outDir dist src/*.ts

FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY --from=build /app/dist ./dist
USER node
EXPOSE 8080
CMD ["node", "dist/server.js"]
