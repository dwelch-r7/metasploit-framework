FROM node@sha256:47725aca53d3295ec2d3be8f62726599b3033cc262edc2c7e429909b3ac599fc AS dependencies
ARG NEXT_VERSION=15.2.2
WORKDIR /srv/next
ENV NEXT_TELEMETRY_DISABLED=1 NODE_OPTIONS=--max-old-space-size=384 RAYON_NUM_THREADS=1 UV_THREADPOOL_SIZE=2
COPY packages/${NEXT_VERSION}/package*.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM dependencies AS application
ARG MIDDLEWARE_LAYOUT=root
COPY application /fixture
# Keep the real middleware location visible to Next's production compiler.
RUN case "$MIDDLEWARE_LAYOUT" in root) destination=/srv/next ;; src) destination=/srv/next/src ;; *) exit 1 ;; esac \
    && mkdir -p "$destination/pages" \
    && cp -R /fixture/pages/. "$destination/pages/" \
    && cp /fixture/middleware.js "$destination/" \
    && cp /fixture/next.config.js /srv/next/ \
    && npm run build \
    && chown -R node:node /srv/next/.next
USER node
EXPOSE 3000
CMD ["node", "node_modules/next/dist/bin/next", "start", "-H", "0.0.0.0", "-p", "3000"]
