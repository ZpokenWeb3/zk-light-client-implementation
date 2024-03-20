FROM node:current-alpine

WORKDIR /app

COPY package.json yarn.lock .env /app

RUN yarn install

COPY ./src /app/src
COPY ./prisma /app/prisma
COPY ./proofs /app/proofs

RUN yarn db:push

ENV NATS_URL=nats://195.189.60.190:4222

EXPOSE 9024
CMD yarn start