FROM nginx:alpine

# Same-origin API proxy (fixes cross-origin session cookies) + static assets.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY . /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
