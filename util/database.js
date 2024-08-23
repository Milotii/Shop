const Sequelize = require('sequelize');

const sequelize = new Sequelize('node-complete', 'root', 'admin253', {
    dialect: 'mysql', 
    host: 'localhost'
});

module.exports = sequelize;