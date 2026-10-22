FROM node:22-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS build
WORKDIR /repo
COPY packages ./packages
COPY web ./web
WORKDIR /repo/web
RUN npm ci && npm run build

FROM nginx:1.30.6-alpine-slim@sha256:a6cc4968d63e87b7d78fb0e089dcd85a6c88e7660b9b06ee0c9b380ac7bc5593
COPY --from=build /repo/web/dist /usr/share/nginx/html
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
