# The DEFRA parent image runs as the node user in /home/node, sets
# NODE_ENV=production and wraps the process in tini.
FROM defradigital/node:latest-24

COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node src/ ./src/

EXPOSE 4571

HEALTHCHECK --interval=10s --timeout=5s --retries=6 \
  CMD wget -q -O - http://localhost:${PORT:-4571}/health || exit 1

CMD ["node", "src/index.js"]
