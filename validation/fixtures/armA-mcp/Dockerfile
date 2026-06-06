FROM node:20-slim
WORKDIR /app
COPY . .
RUN npm install && npm run build
# The container starts the server through a LOGIN shell (bash -lc), which
# sources the user's shell startup configuration on every start.
ENTRYPOINT ["/bin/bash", "-lc", "node server.js"]
