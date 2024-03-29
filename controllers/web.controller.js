//WebController.js
/*-------------------------------------------------
Componente: Procedimientos No Transaccionales
-------------------------------------------------*/
const mysql = require("mysql");
const sc = require("../database/StringConection");
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const mime = require('mime');
const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
});
const db = require("../database/db.js");

const ouUsuario = require("../models/sgm_usuarios.js");
const onTabParametros = require("../models/sgm_tabparametros.js");
//get all data api with store procedure

const directorioBase = 'assets/documents/categoria';
let currentIndex = 2; // Contador global para el campo "index"
let roles = ' Root, All, Users, Admin ';

const estructuraInicial = [
  {
    id: '1',
    index: currentIndex++,
    tabID: currentIndex,
    tabName: 'Inicio',
    title: '',
    description: '',
    parentId: -1,
    level: 0,
    authorizedRoles: '65;-1;',
    authorizedRolesAllString: ' Root, All, Users, Admin ',
    administratorRoles: '65;',
    tabOrder: 1,
    isVisible: true,
    componentName: '',
    routeName: 'gestcon',
    isDisabled: false,
    isDeleted: false,
    wasUpdated: false,
    security: false,
    path: 'gestcon',
    tabChildren: [],
  },
  {
    id: '2',
    index: currentIndex++,
    tabID: currentIndex,
    tabName: 'Mantenimiento - Usuarios',
    title: '',
    description: '',
    parentId: -1,
    level: 0,
    authorizedRoles: '65;-1;',
    authorizedRolesAllString: ' Root ',
    administratorRoles: '65;',
    tabOrder: 1,
    isVisible: true,
    componentName: '',
    routeName: 'MantUsuario',
    isDisabled: false,
    isDeleted: false,
    wasUpdated: false,
    security: false,
    path: 'MantUsuario',
    tabChildren: [],
  },
  {
    id: '3',
    index: currentIndex++,
    tabID: currentIndex,
    tabName: 'Mantenimiento - Restricciones',
    title: '',
    description: '',
    parentId: -1,
    level: 0,
    authorizedRoles: '65;-1;',
    authorizedRolesAllString: ' Root ',
    administratorRoles: '65;',
    tabOrder: 1,
    isVisible: true,
    componentName: '',
    routeName: 'MantRestric',
    isDisabled: false,
    isDeleted: false,
    wasUpdated: false,
    security: false,
    path: 'MantRestric',
    tabChildren: [],
  },
  {
    id: String(currentIndex),
    index: currentIndex++,
    tabID: currentIndex,
    portalID: 9,
    tabName: 'Documentos',
    title: '',
    description: '',
    parentId: 1,
    level: 0,
    authorizedRoles: '65;68;-3;',
    authorizedRolesAllString: ' Root, All, Users, Admin ',
    administratorRoles: '65;',
    tabOrder: 2,
    isVisible: true,
    componentName: '',
    routeName: 'categoria',
    isDisabled: false,
    isDeleted: false,
    wasUpdated: false,
    security: false,
    path: 'categoria',
    tabChildren: leerDirectorio('', currentIndex, 1), // Llama a la función para generar la estructura de "Categoria"
  },

];


const bytesToSize = (bytes) => {
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  if (bytes === 0) return '0 Byte';
  const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
  return Math.round(100 * (bytes / Math.pow(1024, i))) / 100 + ' ' + sizes[i];
};

const getDirectory = async (request, response) => {
  try {
    //const estructura = JSON.stringify(estructuraInicial, null, 2);
    const estructura = estructuraInicial;

    response.json(estructura);

  } catch (error) {
    response.status(500);
    response.send(error.message);
  } finally {
  }

}

function leerDirectorio(dir, parent, level, _roles, _security) {
  const rutaCompleta = path.join(directorioBase, dir);
  const directorios = fs.readdirSync(rutaCompleta)
    .filter(item => fs.statSync(path.join(rutaCompleta, item)).isDirectory());

  const elementos = [];

  directorios.forEach((directorio, i) => {
    const rutaArchivo = path.join(rutaCompleta, directorio);
    const rutaDirectorio = path.join(dir, directorio);

    const resultado = rutaDirectorio.replace(new RegExp('^' + directorioBase.replace(/[\\\/]/g, '\\\\')), '');


    let _Roles = _roles ?? roles;
    let _Security = _security ?? false;
    //console.log(directorio);

    if (directorio == "sistemas") {
      _Roles = ' Root ';
      _Security = true;
    }

    if (directorio == "gerencia") {
      _Roles = ' Root, Admin ';
      _Security = true;
    }


    const elemento = {
      id: String(currentIndex),
      index: currentIndex++,
      tabID: currentIndex,
      portalID: 9,
      tabName: directorio,
      title: '',
      description: '',
      parentId: parent,
      level: level,
      authorizedRoles: '65;68;-3;',
      authorizedRolesAllString: _Roles,
      administratorRoles: '65;',
      tabOrder: i + 1,
      isVisible: true,
      componentName: '',
      routeName: 'categoria?path=' + resultado.toLowerCase(),
      isDisabled: false,
      isDeleted: false,
      wasUpdated: false,
      security: _Security,
      path: resultado.toLowerCase(),
      tabChildren: leerDirectorio(rutaDirectorio, currentIndex, level + 1, _Roles, _Security),
    };

    elementos.push(elemento);
  });

  return elementos;

}



const getPathv2 = async (req, res) => {
  const category = req.query.category;

  //console.log(category);

  if (!category) {
    return res.status(400).json({ error: 'Falta el parámetro "category" en la solicitud.' });
  }

  try {
    const categoryPath = path.join(__dirname, '..', 'assets', 'documents', 'categoria', category);

    fs.readdir(categoryPath, (err, files) => {
      if (err) {
        return res.status(500).json({ error: 'Error al leer la carpeta.' });
      }

      const fileDetails = files.map(file => {
        const filePath = path.join(categoryPath, file);
        const stats = fs.statSync(filePath);

        const fechaHora = new Date(stats.mtime);
        const dia = fechaHora.getDate().toString().padStart(2, '0');
        const mes = (fechaHora.getMonth() + 1).toString().padStart(2, '0');
        const anio = fechaHora.getFullYear();
        const horas = fechaHora.getHours().toString().padStart(2, '0');
        const minutos = fechaHora.getMinutes().toString().padStart(2, '0');
        const segundos = fechaHora.getSeconds().toString().padStart(2, '0');

        return {
          id: uuidv4(),
          fileName: file,
          fileSize: bytesToSize(stats.size),
          lastModified: `${dia}/${mes}/${anio} ${horas}:${minutos}:${segundos}`,
        };
      });

      res.json({ files: fileDetails });
    });
  } catch (error) {
    console.error('Error reading folder:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};


const obtenerRutaDelArchivo = (category, document) => {
  // Lógica para obtener la ruta del archivo
  const filePath = path.join(__dirname, '..', 'assets', 'documents', 'categoria', category, document);

  // Enviar el archivo al cliente
  return filePath;
};

const serveFile = (req, res) => {
  const category = req.query.category;
  const document = req.query.document;

  const filePath = obtenerRutaDelArchivo(category, document);

  //console.log(filePath);

  if (!filePath) {
    return res.status(404).json({ error: 'Archivo no encontrado.' });
  }

  // Obtener la extensión del archivo
  const fileExtension = path.extname(document).toLowerCase();

  // Configurar las cabeceras de tipo de contenido
  if (fileExtension === '.pdf' || (fileExtension === '.jpg' || fileExtension === '.jpeg' || fileExtension === '.png'
    || fileExtension === '.bmp' || fileExtension === '.mp4' || fileExtension === '.wav' || fileExtension === '.mp3')) {
    // Para PDF e imágenes, abrir en el navegador
    res.setHeader('Content-Disposition', 'inline');
  } else {
    // Para otras extensiones, descargar el archivo
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(document)}"`);
  }

  // Configurar el tipo de contenido según la extensión
  if (fileExtension === '.docx') {
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  } else if (fileExtension === '.xlsx') {
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');


  } else if (fileExtension === '.pptx') {
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.presentationml.presentation');
  } else if (fileExtension === '.pdf') {
    res.setHeader('Content-Type', 'application/pdf');
  } else if (fileExtension === '.jpg' || fileExtension === '.jpeg') {
    res.setHeader('Content-Type', 'image/jpeg');
  } else if (fileExtension === '.png') {
    res.setHeader('Content-Type', 'image/png');
  } else if (fileExtension === '.mp4') {
    res.setHeader('Content-Type', 'video/mp4');
    // Aquí deberías enviar el archivo al cliente, por ejemplo, con res.sendFile()
  } else if (fileExtension === '.wav') {
    res.setHeader('Content-Type', 'video/wav');
    // Aquí deberías enviar el archivo al cliente, por ejemplo, con res.sendFile()
  } else if (fileExtension === '.mp3') {
    res.setHeader('Content-Type', 'audio/mp3');
    // Aquí deberías enviar el archivo al cliente, por ejemplo, con res.sendFile()
  }

  // Enviar el archivo al cliente
  res.sendFile(filePath);
};


const getUsuario = async (request, response) => {



  let connection;
  try {
    // create mysql connection
    connection = await mysql.createConnection(sc.dbStringConection());

    var params = request.body;


    ouUsuario.Accion = params.Accion;
    ouUsuario.Sgm_cUsuario = params.Sgm_cUsuario;
    ouUsuario.Sgm_cNombre = params.Sgm_cNombre;
    ouUsuario.Sgm_cContrasena = params.Sgm_cContrasena;
    ouUsuario.Sgm_cObservaciones = params.Sgm_cObservaciones;
    ouUsuario.Sgm_cPerfil = params.Sgm_cPerfil;
    ouUsuario.Sgm_cAccesodeSubida = params.Sgm_cAccesodeSubida;

    
    
   //console.log(ouUsuario.Accion);
   //console.log("--------------");

    connection.query("CALL sp_sgm_usuarios (?,?,?,?,?,?,?) ", [
      ouUsuario.Accion, ouUsuario.Sgm_cUsuario, ouUsuario.Sgm_cNombre,
      ouUsuario.Sgm_cContrasena, ouUsuario.Sgm_cObservaciones, ouUsuario.Sgm_cPerfil,
      ouUsuario.Sgm_cAccesodeSubida

      
    ], function (error, results, fields) {

      if (error) {

        response.json({ error: error.message });

      } else {



        response.json(results);
      }
    });
  } catch (error) {
    response.status(500);
    response.send(error.message);
  } finally {
    if (connection) {
      connection.end();
    }
  }
};

const getTabParametros = async (request, response) => {



  let connection;
  try {
    // create mysql connection
    connection = await mysql.createConnection(sc.dbStringConection());

    var params = request.body;


    onTabParametros.Accion = params.Accion;
    onTabParametros.Sgm_cRestricciones = params.Sgm_cRestricciones;
    onTabParametros.Sgm_cTipo = params.Sgm_cTipo;


    connection.query("CALL sp_sgm_tabparametros (?,?,?) ", [
      onTabParametros.Accion, onTabParametros.Sgm_cRestricciones, onTabParametros.Sgm_cTipo
    ], function (error, results, fields) {

      if (error) {

        response.json({ error: error.message });

      } else {



        response.json(results);
      }
    });
  } catch (error) {
    response.status(500);
    response.send(error.message);
  } finally {
    if (connection) {
      connection.end();
    }
  }
};


const handleFileUpload = async (req, res) => {
  try {
    // Utiliza multer para manejar la carga de archivos
    upload.array('file')(req, res, (err) => {
      if (err) {
        console.error('Error al cargar los archivos:', err.message);
        return res.status(500).json({ error: 'Error en la carga de archivos.' });
      }

      // Verifica que req.files y req.body estén definidos
      if (!req.files || !req.body.urlDestino) {
        return res.status(400).json({ error: 'Falta el parámetro "files" o "urlDestino" en la solicitud.' });
      }

      const files = req.files;

      // Itera sobre cada archivo y guarda en el sistema de archivos
      for (const file of files) {
        const _filename = file.originalname; // Utiliza el nombre original del archivo proporcionado por multer

        // Utiliza obtenerRutaDelArchivo con la categoría proporcionada
        let categoryPath = obtenerRutaDelArchivo(req.body.urlDestino, '');
        const filePath = path.join(categoryPath, _filename);

        // Verifica si el archivo ya existe en la ruta especificada
        if (fs.existsSync(filePath)) {
          return res.status(400).json({ error: `El archivo ${_filename} ya existe en la ruta especificada.` });
        }

        // Escribe el archivo al sistema de archivos
        fs.writeFile(filePath, file.buffer, (err) => {
          if (err) {
            console.error('Error al escribir el archivo en el sistema de archivos:', err);
            return res.status(500).json({ error: 'Error en la carga de archivos.' });
          }
        });
      }

      // Envia una única respuesta después de procesar los archivos
      return res.status(200).json({ message: 'Archivos subidos con éxito.' });
    });
  } catch (error) {
    console.error('Error en la carga de archivos:', error.message);
    return res.status(500).json({ error: 'Error en la carga de archivos.' });
  }
};




// export functions
module.exports = {
  getUsuario,
  obtenerRutaDelArchivo,
  serveFile,
  getPathv2,
  getDirectory,
  handleFileUpload,
  getTabParametros,
};