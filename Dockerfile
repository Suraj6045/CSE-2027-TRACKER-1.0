FROM node:20-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
ENV NODE_ENV=production PORT=3000 DB_PATH=/data/tracker.db
VOLUME /data
EXPOSE 3000
CMD ["node", "server.js"]
