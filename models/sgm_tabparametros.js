const db = require("../database/db.js");
const DataTypes = require("sequelize");
const Sequelize = require("sequelize");

const sequelize = new Sequelize('mysql::memory:')

const sgm_tabparametros = sequelize.define('sgm_tabparametros', {
    Accion: { type: DataTypes.STRING },    
    Sgm_cRestricciones: { type: DataTypes.STRING },
    Sgm_cTipo: { type: DataTypes.STRING },

})

module.exports = sgm_tabparametros;


