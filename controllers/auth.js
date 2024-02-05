const db = require("../database/db.js");
const JWT = require("jsonwebtoken");
const CryptoJS = require("crypto-js");

function getValidacion(Accion, user, password) {
  const connection = db.getConnection();
  return new Promise((resolve, reject) => {
    connection.query(
      "CALL sp_sgm_usuarios (?, ?, ?, ?, ?, ?, ?) ",
      [Accion, user, "", password, "", "", ""],
      function (error, results, fields) {
        if (error) {
          reject(error);
        } else {
          resolve(results);
        }
      }
    );
  });
}

const generateAccessToken = (Sgm_cUsuario) => {
  return JWT.sign({ Sgm_cUsuario }, "nfb32iur32ibfqfvi3vf932bg932g932", {
    expiresIn: 360000,
  });
};

const generateAccesoSubidaEncriptado = (Sgm_cUsuario) => {
  return CryptoJS.AES.encrypt('A' + Sgm_cUsuario, 'nfb32iur32ibfqfvi3vf932bg932g932').toString();
};

const token = async (request, response) => {
    try {
      const { Sgm_cUsuario, Sgm_cContrasena } = request.body;

      const _result = await getValidacion("VALIDARUSUARIO", Sgm_cUsuario, Sgm_cContrasena);

      let token = "";
      let accUp = "";

      if (_result && _result[0].length > 0) {
        if (_result[0][0].Sgm_cUsuario) {
          token = generateAccessToken(Sgm_cUsuario);
          accUp = generateAccesoSubidaEncriptado(Sgm_cUsuario);
        } else {
          return response.status(422).json({
            errors: [
              {
                msg: "This user already not exists",
              },
            ],
          });
        }
      } else {
        return response.status(422).json({
          errors: [
            {
              msg: "This user already not exists",
            },
          ],
        });
      }

      response.json({
        token,
        accUp, // Deberías enviar accUp en la respuesta
      });
    } catch (error) {
      response.status(500);
      response.send(error.message);
    }
};

  
  module.exports = {
    token,
  };
  