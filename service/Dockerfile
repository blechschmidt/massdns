FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY src ./src
COPY public ./public
EXPOSE 8080
ENV NODE_ENV=production
CMD ["node", "src/server.js"]
