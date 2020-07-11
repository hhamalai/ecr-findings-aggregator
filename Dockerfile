FROM nginx

COPY web/dist /usr/share/nginx/html
COPY docker/default.conf /etc/nginx/conf.d/