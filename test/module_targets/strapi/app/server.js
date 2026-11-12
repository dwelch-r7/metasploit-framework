const instance = require('strapi')({dir: process.cwd(), serveAdminPanel: false, autoReload: false});
instance.start();
