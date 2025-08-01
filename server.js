import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import unzipper from 'unzipper';
import multer from 'multer';
import { exec } from 'child_process';
import { fileURLToPath } from 'url';
import { pool, pooluser } from './src/db/connections.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import './src/db/schema.js';
import AdmZip from 'adm-zip';
import axios from 'axios';
import cookieParser from 'cookie-parser';

dotenv.config();
const app = express();

app.use(cookieParser());


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());



// Configure multer

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    // Use the original filename (without any modifications)
    cb(null, file.originalname);
  }
});
const upload = multer({
  storage,
  dest: 'uploads/',
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/zip' || file.mimetype === 'application/x-zip-compressed') {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only ZIP files are allowed.'));
    }
  }
});

// 🟢 JWT Middleware
function authenticateJWT(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// 🟢 JWT Middleware using Cookie
function authenticateJWTFromCookie(req, res, next) {
  const token = req.cookies?.token; // Read from 'token' cookie

  if (!token) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user;
    next();
  });
}

// 🟢 JWT Middleware using either Cookie or token
function authenticateJWTEither(req, res, next) {
  const headerToken = req.headers['authorization']?.split(' ')[1];
  const cookieToken = req.cookies?.token;

  // Try header token first
  if (headerToken) {
    jwt.verify(headerToken, process.env.JWT_SECRET, (err, user) => {
      if (!err) {
        req.user = user;
        return next(); // ✅ Header token valid
      }

      // If header token fails, try cookie token
      if (cookieToken) {
        jwt.verify(cookieToken, process.env.JWT_SECRET, (cookieErr, cookieUser) => {
          if (!cookieErr) {
            req.user = cookieUser;
            return next(); // ✅ Cookie token valid
          }
          return res.sendStatus(403); // ❌ Both invalid
        });
      } else {
        return res.sendStatus(403); // ❌ Header failed & no cookie
      }
    });
  } else if (cookieToken) {
    // Try cookie token directly if no header token
    jwt.verify(cookieToken, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403); // ❌ Invalid
      req.user = user;
      next(); // ✅ Cookie token valid
    });
  } else {
    return res.sendStatus(401); // ❌ No token at all
  }
}

// 🔐 Login route
app.post('/', async (req, res) => {
  const { username, password } = req.body;
  // console.log(req.body);
  try {
    const result = await pooluser.query('SELECT * FROM credentials WHERE username = $1', [username]);
    const client = result.rows[0];
    // console.log(client);
    const role = result.rows[0].role;

    if (!client || username != client.username || !(await bcrypt.compare(password, client.password))) {
      const data = { message: 'Invalid Credentials!!', title: "Oops?", icon: "warning", redirect: "/" };
      return res.status(401).json(data);
    }

    const token = jwt.sign({ username: username, role: role }, process.env.JWT_SECRET, { expiresIn: '2h' });

    // cookie for automatic use
    res.cookie('token', token, {
      httpOnly: true,     // not accessible via JavaScript
      secure: true,      // set to true in production with HTTPS
      sameSite: 'Strict',
      maxAge: 2 * 60 * 60 * 1000 // 2 hours
    });
    // send token
    res.json({ token });
  } catch (error) {
    res.status(500).json({ "message": "server Error" })
  }

});


// 📁 List departments
app.get('/api', authenticateJWT, async (req, res) => {

  try {
    const result = await pooluser.query(`
  SELECT department, COUNT(*) AS layer_count
  FROM layer_metadata
  GROUP BY department
  ORDER BY department ASC
`);
    console.log(result.rows);
    // console.log(result.rows);
    res.status(200).json(result.rows.map(r => ({
      department: r.department,
      count: Number(r.layer_count)
    })));
  } catch (error) {
    res.status(500).json({ "message": "server Error" })
  }
});

// 📂 List layers in a department
app.get('/api/:department', authenticateJWT, async (req, res) => {
  const { department } = req.params;
  // console.log(req.params);
  try {
    const result = await pooluser.query(
      'SELECT layer_name FROM layer_metadata WHERE department = $1',
      [department]
    );
    res.status(200).json(result.rows);
  } catch (error) {
    res.status(500).json({ "message": "server Error" })
  }
});

// 🌍 Get GeoJSON of a layer
app.get('/api/:department/:layer', authenticateJWT, async (req, res) => {
  const { department, layer } = req.params;
  try {

    // Check if 'geom' column exists in the table
    const geomCheck = await pool.query(`
  SELECT column_name
  FROM information_schema.columns
  WHERE table_name = $1 AND column_name = 'geom'
`, [layer]);

    let query;
    if (geomCheck.rows.length > 0) {
      // 'geom' column exists
      // console.log("column exists");

      query = `
    SELECT *, ST_AsGeoJSON(geom)::json AS geometry
    FROM "${layer}"
  `;
    } else {
      // console.log("Fallback: use latitude and longitude");

      // Fallback: use latitude and longitude
      query = `
    SELECT *, 
      json_build_object(
        'type', 'Point',
        'coordinates', json_build_array(longitude::float, latitude::float)
      ) AS geometry
    FROM "${layer}"
  `;
    }

    const result = await pool.query(query);


    const features = result.rows.map(row => {
      const { geometry, geom, ...props } = row;
      return {
        type: 'Feature',
        geometry,
        properties: props
      };
    });

    res.json({ type: 'FeatureCollection', features });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load layer' });
  }
});

// 📝 Get metadata
app.get('/api/:department/:layer/metainfo', authenticateJWT, async (req, res) => {

  try {
    const { department, layer } = req.params;
    const result = await pooluser.query(
      'SELECT * FROM layer_metadata WHERE department = $1 AND layer_name = $2',
      [department, layer]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Metadata not found' });
    res.json(result.rows[0]);

  } catch (error) {
    res.status(500).json({ error: 'Failed to Get metadata' });
  }
});


// ✏️ Update full metadata (no allowedFields filter; match only by layer_name)
app.post('/api/:department/:layer/metainfo', authenticateJWT, async (req, res) => {
  const { layer } = req.params;
  const metadata = req.body;

  try {
    const fields = Object.keys(metadata);
    const values = fields.map(key => metadata[key]);

    if (fields.length === 0) {
      return res.status(400).json({ error: 'No metadata fields provided.' });
    }

    // Build dynamic SET clause
    const setClause = fields.map((field, i) => `${field} = $${i + 1}`).join(', ');

    const query = `
    UPDATE layer_metadata 
    SET ${setClause} 
    WHERE layer_name = $${fields.length + 1}
  `;

    await pooluser.query(query, [...values, layer]);
    res.status(201).json({ message: 'Metadata updated successfully.' });
  } catch (err) {
    console.error('Metadata update error:', err);
    res.status(500).json({ error: 'Failed to update metadata.' });
  }
});



// ⬆️ Upload shapefile ZIP
app.post('/upload', authenticateJWT, upload.single('file'), async (req, res) => {
  const { department, filename } = req.body;
  const db = 'geodatasets';
  const srid = 4326;

  const client = await pooluser.connect();

  // Unzip
  const zipPath = req.file.path;

  const unzipPath = path.join('uploads', filename);
  try {
    // Check if layer already exists
    const check = await client.query(`SELECT 1 FROM layer_metadata WHERE layer_name = $1`, [filename]);
    if (check.rowCount > 0) {
      return res.status(400).json({ message: 'Shapefile name already exists' });
    }
    const basedir = 'uploads/'
    const zip = new AdmZip(req.file.path);
    const fullDirectoryPath = path.join(basedir, filename)

    zip.extractAllTo(fullDirectoryPath, true);

    const tmpshppath0 = fullDirectoryPath + '\\' + req.file.originalname;

    const tmpshppath = path.normalize(tmpshppath0);
    // Extract the file name without the extension
    const shapefilePath = tmpshppath.replace(".zip", ".shp");

    new AdmZip(zipPath).extractAllTo(unzipPath, true);

    // Find .shp file
    const shpFile = fs.readdirSync(unzipPath).find(f => f.endsWith('.shp'));
    const shxFile = fs.readdirSync(unzipPath).find(f => f.endsWith('.shx'));
    const dbfFile = fs.readdirSync(unzipPath).find(f => f.endsWith('.dbf'));
    if (!shpFile) throw new Error('No .shp file found in zip');
    if (!shxFile) throw new Error('No .shx file found in zip');
    if (!dbfFile) throw new Error('No .dbf file found in zip');

    const shpPath = path.join(unzipPath, shpFile);
    const cmd = `shp2pgsql -I -s ${srid} "${shpPath}" ${filename} | psql -U ${process.env.db_user} -d ${process.env.db_name}`;

    // Upload to DB
    exec(cmd, { env: { ...process.env, PGPASSWORD: process.env.db_pw } }, async (err, stdout, stderr) => {
      cleanUp(zipPath, unzipPath);

      if (err) {
        console.error(stderr);
        return res.status(500).json({ message: 'Error uploading shapefile' });
      }



      // Insert metadata
      await client.query(
        `INSERT INTO layer_metadata (department, layer_name)
         VALUES ($1, $2)`,
        [department, filename]
      );



      res.status(201).json({ message: 'Shapefile uploaded successfully' });
    });
  } catch (err) {
    cleanUp(zipPath, unzipPath);
    // console.error(err);
    res.status(500).json({ title: "Failed", message: err.message });
  } finally {
    client.release();
  }
});

// ⬆️ rEPLACE shapefile ZIP
app.post('/replace', authenticateJWT, upload.single('file'), async (req, res) => {
  // console.log("replce-------------------------");

  const { filename } = req.body;
  // console.log(req.body);

  const srid = 4326;
  const zipPath = req.file.path;
  const unzipPath = path.join('uploads', filename + '_replace');
  const client = await pooluser.connect();
  try {
    const check = await client.query(`SELECT 1 FROM layer_metadata WHERE layer_name = $1`, [filename]);
    if (check.rowCount === 0) {
      return res.status(404).json({ message: 'Layer not found in metadata. Cannot replace.' });
    }

    // Extract uploaded zip


    new AdmZip(zipPath).extractAllTo(unzipPath, true);

    const shpFile = fs.readdirSync(unzipPath).find(f => f.endsWith('.shp'));
    const shxFile = fs.readdirSync(unzipPath).find(f => f.endsWith('.shx'));
    const dbfFile = fs.readdirSync(unzipPath).find(f => f.endsWith('.dbf'));
    if (!shpFile) throw new Error('No .shp file found in zip');
    if (!shxFile) throw new Error('No .shx file found in zip');
    if (!dbfFile) throw new Error('No .dbf file found in zip');

    const shpPath = path.join(unzipPath, shpFile);
    console.log(shpPath);


    // Drop + recreate table
    const dropCmd = `psql -U ${process.env.db_user} -d ${process.env.db_name} -c "DROP TABLE IF EXISTS ${filename} CASCADE;"`;
    const importCmd = `shp2pgsql -I -s ${srid} "${shpPath}" ${filename} | psql -U ${process.env.db_user} -d ${process.env.db_name}`;



    exec(dropCmd, { env: { ...process.env, PGPASSWORD: process.env.db_pw } }, (dropErr, dropStdout, dropStderr) => {
      if (dropErr) {
        cleanUp(zipPath, unzipPath);

        console.error('DROP error:', dropStderr);
        return res.status(500).json({ message: 'Failed to drop existing table' });
      }

      exec(importCmd, { env: { ...process.env, PGPASSWORD: process.env.db_pw } }, async (importErr, importStdout, importStderr) => {
        cleanUp(zipPath, unzipPath);

        if (importErr || importStderr.toLowerCase().includes('error')) {
          console.error('Import error:', importStderr || importErr);
          return res.status(500).json({ message: 'Failed to import new shapefile' });
        }

        res.status(200).json({ message: 'Layer replaced successfully' });
      });
    });


  } catch (err) {
    console.error(err);
    cleanUp(zipPath, unzipPath)
    res.status(500).json({ title: "Failed", message: err.message, icon: 'Danger' });
  } finally {
    client.release();
  }
});

// 🔄 Cleanup helper
function cleanUp(zipPath, unzipPath) {
  try {
    if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath); // Delete zip file
    if (fs.existsSync(unzipPath)) fs.rmSync(unzipPath, { recursive: true, force: true }); // Delete extracted folder
    console.log('Cleanup successful');
  } catch (err) {
    console.error('Cleanup failed:', err);
  }
}


// Delete a layer completely
app.post('/delete/:department/:layer', async (req, res) => {
  const { department, layer } = req.params;
  const client = await pooluser.connect();
  const dataclient = await pool.connect();

  try {
    // Check if layer exists in metadata
    const check = await client.query(`SELECT * FROM layer_metadata WHERE layer_name = $1`, [layer]);
    if (check.rowCount === 0) {
      return res.status(404).json({ message: 'Layer not found in metadata' });
    }

    // Delete PostGIS table
    await dataclient.query(`DROP TABLE IF EXISTS "${layer}" CASCADE`);

    // Delete metadata
    await client.query(`DELETE FROM layer_metadata WHERE layer_name = $1`, [layer]);

    // Delete file from catalog folder
    const zipPath = path.join(process.cwd(), 'catalog', `${layer}.zip`);
    if (fs.existsSync(zipPath)) {
      fs.unlinkSync(zipPath);
    }

    res.status(200).json({ message: `Layer "${layer}" deleted successfully.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ title: 'Failed', message: err.message });
  } finally {
    client.release();
    dataclient.release();
  }
});


// wfs
app.get('/api/:department/:layer/wfs', authenticateJWT, async (req, res) => {
  const { department, layer } = req.params;

  const geoserverURL = process.env.geoserverURL;
  const workspace = process.env.workspace; // 🔁 optionally map department to workspace

  const wfsURL = `${geoserverURL}/${workspace}/ows?service=WFS&version=1.0.0&request=GetFeature&typeName=${workspace}:${layer}&outputFormat=application/json`;

  try {
    const geores = await fetch(wfsURL, {
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${process.env.geoserveruser}:${process.env.geoserverpassword}`).toString('base64')
      }
    });
    const data = await geores.json();
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json(data);
  } catch (error) {
    console.error('WFS proxy error:', error);
    res.status(500).json({ error: 'Failed to fetch WFS data from GeoServer' });
  }
});

// kml
app.get('/api/:department/:layer/kml', authenticateJWTEither, async (req, res) => {
  const { department, layer } = req.params;

  const geoserverURL = process.env.geoserverURL;
  const workspace = process.env.workspace; // 🔁 optionally map department to workspace

  const wfsURL = `${geoserverURL}/${workspace}/ows?service=WFS&version=1.0.0&request=GetFeature&typeName=${workspace}:${layer}&outputFormat=kml`;

  try {
    const geores = await fetch(wfsURL, {
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${process.env.geoserveruser}:${process.env.geoserverpassword}`).toString('base64')
      }
    });
    const kmlData = await geores.text(); // KML is XML-based
    res.setHeader("Content-Type", "application/vnd.google-earth.kml+xml");
    res.setHeader("Content-Disposition", "attachment; filename=layer-data.kml");
    res.status(200).send(kmlData);
  } catch (error) {
    console.error('WFS proxy error:', error);
    res.status(500).json({ error: 'Failed to fetch KML data from GeoServer' });
  }
});

// wms

app.get('/viewer/:department/:layer', authenticateJWTFromCookie, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'wmsviewer.html'));
});



// WMS Proxy Route
app.get('/wms', authenticateJWT, async (req, res) => {
  const { workspace } = req.query;

  if (!workspace) {
    return res.status(400).json({ error: 'Missing "workspace" parameter' });
  }

  // Remove `workspace` from query string and forward the rest to GeoServer
  const originalQuery = req._parsedUrl.query;
  const queryParams = originalQuery.replace(`workspace=${workspace}&`, '');
  const geoServerUrl = `http://localhost:8080/geoserver/${workspace}/wms?${queryParams}`;
  // console.log(geoServerUrl);

  try {
    const response = await axios.get(geoServerUrl, {
      responseType: 'arraybuffer', // Important for image/tile responses
    });

    // Pass headers like content-type and others from GeoServer to client
    Object.entries(response.headers).forEach(([key, value]) => {
      res.setHeader(key, value);
    });

    res.status(response.status).send(response.data);
  } catch (err) {
    console.error('WMS Proxy Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch WMS from GeoServer' });
  }
});

app.get('/verify-token', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    res.sendStatus(200); // Token valid
  });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token'); // Match name & options (path/domain)
  res.status(200).json({ message: 'Logged out' });
});


app.get('/', (req, res) => {
  res.redirect('/login.html');
});
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/home.html', authenticateJWTFromCookie, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/department.html', authenticateJWTFromCookie, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'department.html'));
});



const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
