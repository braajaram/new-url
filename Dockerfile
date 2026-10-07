FROM node:22-bookworm-slim

WORKDIR /app/applet
COPY package*.json ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npm run build

EXPOSE 3000
CMD ["node", "server.js"]
