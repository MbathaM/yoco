FROM node:16

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install

COPY . .

EXPOSE 3000

ENV NODE_ENV=development

CMD ["npm", "start"]
