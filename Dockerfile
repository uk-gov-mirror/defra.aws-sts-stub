FROM node:24-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src/ ./src/

EXPOSE 4571

HEALTHCHECK --interval=10s --timeout=5s --retries=6 \
  CMD wget -q -O - http://localhost:${PORT:-4571}/health || exit 1

USER node

CMD ["node", "src/index.js"]
