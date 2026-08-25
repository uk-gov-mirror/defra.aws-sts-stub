# The stock Node image, pulled from Docker's mirror on ECR Public. The mirror
# allows anonymous pulls, so the org-scoped Docker Hub credentials the
# pipeline holds are never asked to authorise the base image.
FROM public.ecr.aws/docker/library/node:24-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src/ ./src/

EXPOSE 4571

HEALTHCHECK --interval=10s --timeout=5s --retries=6 \
  CMD wget -q -O - http://localhost:${PORT:-4571}/health || exit 1

USER node

CMD ["node", "src/index.js"]
