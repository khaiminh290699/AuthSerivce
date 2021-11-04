const knex = require("knex");

const { DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT, MIGRATION_PATH } = process.env;

class DB {
  constructor(){
    this.DB = knex.knex({
      client: "pg",
      connection: {
        host: DB_HOST,
        user: DB_USER,
        password: DB_PASSWORD,
        database: DB_NAME,
        port: DB_PORT, 
      },
      migrations: {
        directory: MIGRATION_PATH
      }
    })
  };
}

module.exports = DB;