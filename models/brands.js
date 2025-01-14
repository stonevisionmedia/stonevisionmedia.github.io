// models/brands.js
'use strict';
const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class Brands extends Model {
    static associate(models) {
      // define association here
    }
  }
  Brands.init({
    name: {
      type: DataTypes.STRING,
      allowNull: false
    },
    description: {
      type: DataTypes.TEXT
    }
  }, {
    sequelize,
    modelName: 'Brands',
  });
  return Brands;
};
