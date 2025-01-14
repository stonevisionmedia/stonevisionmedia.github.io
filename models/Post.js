const { Model, DataTypes } = require('sequelize');
const sequelize = require('../database');  // Import the sequelize instance

class Post extends Model {}

Post.init(
  {
    content: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    scheduledAt: {
      type: DataTypes.DATE,
      allowNull: false,
    },
    mediaUrl: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    BrandId: {
      type: DataTypes.INTEGER,
      references: {
        model: 'Brands',
        key: 'id',
      },
      onDelete: 'SET NULL',
      onUpdate: 'CASCADE',
    },
  },
  {
    sequelize,
    modelName: 'Post',
  }
);

module.exports = Post;
