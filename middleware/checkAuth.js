const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");

module.exports = async (req, res, next) => {
    try {
        const token = req.header('x-auth-token');
        const accUp = req.header('x-auth-accUp');

        // Verifica si ambos tokens están presentes
        if (!token || !accUp) {
            return res.status(400).json({
                errors: [
                    {
                        msg: "No token or accUp found"
                    }
                ]
            });
        }

        // Verifica si el token es válido
        let user;
        try {
            user = await jwt.verify(token, "nfb32iur32ibfqfvi3vf932bg932g932");
        } catch (error) {
            return res.status(400).json({
                errors: [
                    {
                        msg: 'Invalid Token'
                    }
                ]
            });
        }

        // Descifra accUp
        let decryptedAccUp;
        try {
            decryptedAccUp = CryptoJS.AES.decrypt(accUp, 'nfb32iur32ibfqfvi3vf932bg932g932').toString(CryptoJS.enc.Utf8);
        } catch (error) {
            return res.status(400).json({
                errors: [
                    {
                        msg: 'Invalid accUp decryption'
                    }
                ]
            });
        }

        // Realiza la validación específica de accUp según tus criterios
        // En este ejemplo, simplemente verifica si es una cadena no vacía
        if (typeof decryptedAccUp !== 'string' || decryptedAccUp.trim() === '') {
            return res.status(400).json({
                errors: [
                    {
                        msg: 'Invalid accUp format'
                    }
                ]
            });
        }

        // Asigna el usuario a req.user para su uso posterior en la aplicación
        req.user = user.Sgm_cUsuario;
        next();

    } catch (error) {
        res.status(400).json({
            errors: [
                {
                    msg: 'Invalid Token or accUp'
                }
            ]
        });
    }
};
