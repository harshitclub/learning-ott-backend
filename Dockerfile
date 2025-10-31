# Use Node 20 LTS as base image
FROM node:20-alpine

# Set working directory inside container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json first (for caching)
COPY package*.json ./

# Install all dependencies
RUN npm install

# Copy the rest of the project (including prisma folder)
COPY . .

# Build TypeScript
RUN npm run build

# Expose port your app runs on
EXPOSE 3002

# Start app with PM2 in production
CMD ["npm", "run", "pm2:start"]