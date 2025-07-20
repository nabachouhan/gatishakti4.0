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

dotenv.config();
const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, 'public')));
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

// 🔐 Login route
app.post('/', async(req, res) => {
  const { username, password } = req.body;
  // console.log(req.body);
  try {
    const result = await pooluser.query('SELECT * FROM credentials WHERE username = $1', [username]);
      const client = result.rows[0];
      // console.log(client);
      const role = result.rows[0].role;
      
      if ( !client ||username!=client.username || !(await bcrypt.compare(password, client.password))) {
        const data = { message: 'Invalid Credentials!!', title: "Oops?", icon: "warning", redirect:"/" };
        return res.status(401).json(data);
      }
  
    const token = jwt.sign({ username: username, role: role }, process.env.JWT_SECRET, { expiresIn: '2h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({"message":"server Error"})
  }

});


// 📁 List departments
app.get('/api', authenticateJWT, async (req, res) => {
  
try {
  const result = await pooluser.query('SELECT DISTINCT department FROM layer_metadata');
    // console.log(result.rows);
    res.status(200).json(result.rows.map(r => r.department));
} catch (error) {
      res.status(500).json({"message":"server Error"})
}  
});

// 📂 List layers in a department
app.get('/api/:department', authenticateJWT, async (req, res) => {
  const { department } = req.params;
  // console.log(req.params);
  // console.log(`SELECT layer_name FROM layer_metadata WHERE department = ${department};`)
  try {
    const result = await pooluser.query(
      'SELECT layer_name FROM layer_metadata WHERE department = $1',
      [department]
    );
    res.status(200).json(result.rows);
  } catch (error) {
      res.status(500).json({"message":"server Error"})
  }
});

// 🌍 Get GeoJSON of a layer
app.get('/api/:department/:layer', authenticateJWT, async (req, res) => {
  const { department, layer } = req.params;
  try {
    const result = await pool.query(`
      SELECT *, ST_AsGeoJSON(geom)::json AS geometry 
      FROM "${layer}"
    `);

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
app.put('/api/:department/:layer/metainfo', authenticateJWT, async (req, res) => {
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





// ⬆️  update layer
app.put('/:department/:layer/data', authenticateJWT, upload.single('file'), async (req, res) => {
  const { department, layer } = req.params;
  const file = req.file;
  const schema = department.toLowerCase();
  const table = layer.toLowerCase();
  const uploadDir = `uploads/${Date.now()}`;

  try {
    await fs.promises.mkdir(uploadDir, { recursive: true });

    await fs.createReadStream(file.path)
      .pipe(unzipper.Extract({ path: uploadDir }))
      .promise();

    const shpFile = fs.readdirSync(uploadDir).find(f => f.endsWith('.shp'));
    if (!shpFile) throw new Error('No .shp file found');

    const shpPath = path.join(uploadDir, shpFile);
    const sqlFile = path.join(uploadDir, `${table}.sql`);

    // Drop & Create using shp2pgsql
    const shp2pgsqlCmd = `shp2pgsql -s 4326 -I -W "UTF-8" -g geom -d "${shpPath}" "${schema}.${table}" > "${sqlFile}"`;
    await execPromise(shp2pgsqlCmd);

    const psqlCmd = `psql -U ${process.env.DB_USER} -d ${process.env.DB_NAME} -f "${sqlFile}"`;
    await execPromise(psqlCmd);

    // Get geometry info
    const metaRes = await pooluser.query(`
      SELECT srid, type FROM geometry_columns
      WHERE f_table_schema = $1 AND f_table_name = $2
    `, [schema, table]);

    if (metaRes.rowCount === 0) throw new Error('Geometry not found');

    const { srid, type: geometry_type } = metaRes.rows[0];

    // Upsert metadata
    await pooluser.query(`
      INSERT INTO layer_metadata (department, layer_name, srid, geometry_type)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (department, layer_name)
      DO UPDATE SET srid = $3, geometry_type = $4
    `, [department, layer, srid, geometry_type]);

    res.json({ message: 'Layer updated successfully' });

  } catch (err) {
    console.error('Upload failed:', err);
    res.status(500).json({ error: err.message || 'Upload failed' });
  } finally {
    fs.promises.rm(uploadDir, { recursive: true, force: true }).catch(() => {});
    fs.promises.unlink(file.path).catch(() => {});
  }
});

// ⬆️ Upload shapefile ZIP
app.post('/upload', authenticateJWT, upload.single('file'), async (req, res) => {
  const { department,filename  } = req.body;
  const db = 'geodatasets';
const srid = 4326;

    const client = await pooluser.connect();

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
        // -------------

    // Unzip
    const zipPath = req.file.path;

    const unzipPath = path.join('uploads', filename);

    new AdmZip(zipPath).extractAllTo(unzipPath, true);

    // Find .shp file
    const shpFile = fs.readdirSync(unzipPath).find(f => f.endsWith('.shp'));
    if (!shpFile) throw new Error('No .shp file found in zip');

    const shpPath = path.join(unzipPath, shpFile);
    const cmd = `shp2pgsql -I -s ${srid} "${shpPath}" ${filename} | psql -U ${process.env.db_user} -d ${process.env.db_name}`;

    // Upload to DB
    exec(cmd, { env: { ...process.env, PGPASSWORD: process.env.db_pw } }, async (err, stdout, stderr) => {
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
    console.error(err);
    res.status(500).json({ message: 'Upload failed' });
  } finally {
    client.release();
  }
});

// ⬆️ rEPLACE shapefile ZIP
app.post('/replace', authenticateJWT, upload.single('file'), async (req, res) => {
  // console.log("replce-------------------------");
  
  const {filename } = req.body;
  // console.log(req.body);
  
  const srid = 4326;

  const client = await pooluser.connect();
  try {
    const check = await client.query(`SELECT 1 FROM layer_metadata WHERE layer_name = $1`, [filename]);
    if (check.rowCount === 0) {
      return res.status(404).json({ message: 'Layer not found in metadata. Cannot replace.' });
    }

    // Extract uploaded zip
    const zipPath = req.file.path;
    const unzipPath = path.join('uploads', filename + '_replace');
    new AdmZip(zipPath).extractAllTo(unzipPath, true);

    const shpFile = fs.readdirSync(unzipPath).find(f => f.endsWith('.shp'));
    if (!shpFile) throw new Error('No .shp file found');

    const shpPath = path.join(unzipPath, shpFile);

    // Drop + recreate table
const dropCmd = `psql -U ${process.env.db_user} -d ${process.env.db_name} -c "DROP TABLE IF EXISTS ${filename} CASCADE;"`;
const importCmd = `shp2pgsql -I -s ${srid} "${shpPath}" ${filename} | psql -U ${process.env.db_user} -d ${process.env.db_name}`;


exec(dropCmd, { env: { ...process.env, PGPASSWORD: process.env.db_pw } }, (dropErr, dropStdout, dropStderr) => {
  if (dropErr) {
    console.error('DROP error:', dropStderr);
    return res.status(500).json({ message: 'Failed to drop existing table' });
  }

  exec(importCmd, { env: { ...process.env, PGPASSWORD: process.env.db_pw } }, async (importErr, importStdout, importStderr) => {
    if (importErr || importStderr.toLowerCase().includes('error')) {
      console.error('Import error:', importStderr || importErr);
      return res.status(500).json({ message: 'Failed to import new shapefile' });
    }

    res.status(200).json({ message: 'Layer replaced successfully' });
  });
});


  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Replace failed' });
  } finally {
    client.release();
  }
});

// Delete a layer completely
app.delete('/delete/:department/:layer', async (req, res) => {
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
    res.status(500).json({ message: 'Deletion failed' });
  } finally {
    client.release();
    dataclient.release();
  }
});


// wfs
app.get('/preview/:department/:layer/wfs', async (req, res) => {
  const { department, layer } = req.params;

  const geoserverURL = process.env.geoserverURL;
  const workspace = 'gatishakti'; // 🔁 optionally map department to workspace

  const wfsURL = `${geoserverURL}/${workspace}/ows?service=WFS&version=1.0.0&request=GetFeature&typeName=${workspace}:${layer}&outputFormat=application/json`;

  try {
    const geores = await fetch(wfsURL, {
  headers: {
    Authorization: 'Basic ' + Buffer.from('admin:geoserver').toString('base64')
  }});
    const data = await geores.json();
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json(data);
  } catch (error) {
    console.error('WFS proxy error:', error);
    res.status(500).json({ error: 'Failed to fetch WFS data from GeoServer' });
  }
});

// wms

app.get('/viewer/:department/:layer', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'wmsviewer.html'));
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

function execPromise(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, { env: process.env }, (err, stdout, stderr) => {
      if (err) return reject(stderr);
      resolve(stdout);
    });
  });
}

app.get('/', (req, res) => {
  res.redirect('/login.html');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
