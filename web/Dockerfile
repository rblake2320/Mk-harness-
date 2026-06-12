FROM node:22-slim AS build
WORKDIR /repo
COPY packages ./packages
COPY web ./web
WORKDIR /repo/web
RUN npm install && npm run build

FROM nginx:1.27-alpine
COPY --from=build /repo/web/dist /usr/share/nginx/html
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
