FROM nginx:bullseye

# Instalacja modułu headers-more
RUN apt-get update && apt-get install -y \
    --allow-downgrades \
    nginx=1.18.* \
    libnginx-mod-http-headers-more-filter \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
    
# Kopiowanie konfiguracji Nginx
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 443

CMD ["nginx", "-g", "daemon off;"]
