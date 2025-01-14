const { Model, DataTypes } = require('sequelize');
const sequelize = require('../database');  // Import the sequelize instance

class Brand extends Model {}

Brand.init(
  {
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    UserId: {
      type: DataTypes.INTEGER,
      references: {
        model: 'Users',
        key: 'id',
      },
    },
  },
  {
    sequelize,
    modelName: 'Brand',
  }
);

module.exports = Brand;
