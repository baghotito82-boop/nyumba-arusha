FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY src ./src
COPY migrations ./migrations
RUN mkdir -p uploads
EXPOSE 8080
CMD ["node","src/server.js"]
