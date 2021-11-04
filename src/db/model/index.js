const knex = require("knex");
const DB = require("../connect/db")

class Model {
  /**
   * @param {DB} db The date
  */
  constructor(db, trx) {
    this.DB = db.DB || new DB().DB;
    this.trx = trx;
  }

  primaryKey = "id";
  updatedAt = "updated_at";
  createdAt = "create_at";

  openTransaction = async (callback) => {
    return await this.DB.transaction(async (trx) => {
      return await callback(trx);
    })
  }

  /**
   * @returns {knex.Knex} Sum of a and b or an array that contains a, b and the sum of a and b.
   */
  addToTransaction = (query) => {
    if (this.trx) {
      return query.transacting(this.trx);
    }
    return query;
  }
  
  query = () => {
    return this.addToTransaction(this.DB.from(this.tableName))
  }

  findOne = (condition, returnData = ["*"]) => {
    return this.query().where(condition).select(returnData).first();
  }

  insertOne = async (data, returnData = ["*"]) => {
    const result = (await this.addToTransaction(this.DB.insert(data).into(this.tableName).returning(returnData)))[0];
    return result;
  }

  updateOne = async (data, returnData = ["*"]) => {
    data[this.updatedAt] = new Date();
    const result = (await this.addToTransaction(this.DB.update(data).from(this.tableName).where({ [this.primaryKey]: data[this.primaryKey] }).returning(returnData)))[0];
    return result;
  }

  /**
   * @returns {knex.Knex} Sum of a and b or an array that contains a, b and the sum of a and b.
   */
  queryByCondition = (queryBuilder, wheres, page, limit, order = {}) => {
    const operators = {
      "$eq": "=",
      "$ne": "!=",
      "$lt": "<",
      "$gt": ">",
      "$lte": "<=",
      "$gte": ">="
    }
    const query = wheres.reduce((query, where) => {
      let key = Object.keys(where)[0];
      const operator = Object.keys(where[key])[0];
      const value = where[key][operator];

      key = this.DB.raw(`${key}`);

      if (operators[operator]) {
        query.where(key, operators[operator], value)
      }

      switch(operator) {
        case "$empty": {
          if (value) {
            query.whereNull(key);
          } else {
            query.whereNotNull(key);
          }
          break;
        }
        case "$nempty": {
          if (!value) {
            query.whereNull(key);
          } else {
            query.whereNotNull(key);
          }
          break;
        }
        case "$in": {
          query.whereIn(key, value);
          break;
        }
        case "$nin": {
          query.whereNotIn(key, value);
          break;
        }
        case "$between": {
          query.whereBetween(key, value);
          break;
        }
        case "$nbetween": {
          query.whereNotBetween(key, value);
          break;
        }
      }
      return query;
    }, queryBuilder);

    const orderKeys = Object.keys(order);
    orderKeys.reduce((query, orderKey) => {
      query.orderBy(orderKey, order[orderKey] === 1 ? "DESC" : "ASC");
      return query;
    }, query);

    if (limit != null) {
      query.limit(limit).offset((page - 1) * limit);
    }

    return query;
  }

}

module.exports = Model;