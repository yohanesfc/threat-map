FROM node:20-alpine AS builder
WORKDIR /app
ARG NEXT_PUBLIC_API_URL=http://localhost:8090
ARG NEXT_PUBLIC_WS_URL=ws://localhost:8090
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_WS_URL=$NEXT_PUBLIC_WS_URL
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3001
ENV HOSTNAME=0.0.0.0
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
EXPOSE 3001
CMD ["node", "server.js"]
