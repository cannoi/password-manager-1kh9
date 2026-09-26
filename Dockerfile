FROM node:20-alpine

WORKDIR /usr/src/app

# Install only production deps (no native modules -> fast, portable to Pi/ARM)
COPY package*.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY public ./public

ENV PORT=8080
EXPOSE 8080

# Lightweight container-native healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||8080)+'/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD [ "npm", "start" ]
