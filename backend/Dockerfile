FROM node:current-alpine

# Install curl
RUN apk update && apk add --no-cache curl

WORKDIR /app

COPY package.json yarn.lock /app

RUN yarn install

COPY ./src /app/src
COPY ./prisma /app/prisma
COPY ./proofs /app/proofs

RUN yarn db:push

EXPOSE 9024
CMD yarn start
