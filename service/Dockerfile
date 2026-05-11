FROM node:20-alpine
WORKDIR /app
COPY service/package.json ./
RUN npm install --omit=dev
COPY service/src ./src
COPY service/public ./public
EXPOSE 8080
ENV NODE_ENV=production
CMD ["node", "src/server.js"]
