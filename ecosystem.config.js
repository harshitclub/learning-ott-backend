module.exports = {
  apps: [
    {
      name: "ott-backend",
      script: "./dist/index.js",
      instances: "max",
      exec_mode: "cluster",
      watch: "false",
      env_production: {
        NODE_ENV: "production   ",
      },
    },
  ],
};
