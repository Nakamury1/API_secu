import express from "express";
import bcrypt from "bcrypt"
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import axios from "axios";
//import getRawBody from 'raw-body';

dotenv.config();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const shopify_url = process.env.SHOPIFY_URL;
const shopify_access_token = process.env.SHOPIFY_ACCESS_TOKEN;
//const webhook = process.env.WEBHOOK_URL;

const jwt_secret = process.env.JWT_SECRET;
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/health", (req, res) => {
  res.send("Hello world");
});

const loginAttempts = new Map();

// -- Partie 1 --------------------------------------------------------------

app.post('/register', async (req, res) => {
  const {nom, email, password} = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  if (!nom || !email || !password) {
    return res.status(400).json({error: 'Les champs "nom","email" et "password" sont requis'});
  }
  const { data: existingUser } = await supabase
    .from('users')
    .select('id')
    .eq('email', email)
    .single();
  if (existingUser) {
    return res.status(400).json({ error: 'Email déjà utilisé' });
  }
  const { data: userRole } = await supabase
    .from('roles')
    .select('id')
    .eq('nom', 'USER')
    .single();
  
  const {data: newUser, error} = await supabase
    .from('users')
    .insert([{
        nom,
        email,
        password: hashedPassword,
        role_id: userRole.id,
        password_changed_at: new Date().toISOString()
    }])
    .select()
    .single();

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  const token = jwt.sign(
    {userId: newUser.id }, 
    jwt_secret,
    {expiresIn: '1h'});

  res.status(201).json({
    message: 'Utilisateur créé avec succès',
    user: {
      id: newUser.id,
      nom: newUser.nom,
      email: newUser.email
    },
    token
  });
});

// -- Partie 2 & 3 --------------------------------------------------------------

const authenticate = async (req, res, next) => {
  const apiKeyHeader = req.headers['x-api-key'] || req.headers['X-API-KEY'];
  if (apiKeyHeader) {
    const keyHash = crypto.createHash('sha256').update(apiKeyHeader).digest('hex');
    const { data: apiKey, error: apiKeyErr } = await supabase
    .from('api_keys')
    .select('*')
    .eq('api_key', keyHash)
    .single();

    if (apiKeyErr || !apiKey) {
      return res.status(401).json({error:'Clé API invalide ou révoquée'});
    }
    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('*, roles(*)')
      .eq('id', apiKey.user_id)
      .single();

    if (userErr || !user) {
      return res.status(401).json({error:'Utilisateur API non trouvé'});
    }
      req.user = user;
      req.authMethod = 'api_key';
      req.apiKeyId = apiKey.id;
      return next();
  }

    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Token manquant' });
    }
    const decoded = jwt.verify(token, jwt_secret);
    const { data: user, error } = await supabase
      .from('users')
      .select('*, roles(*)')
      .eq('id', decoded.userId)
      .single();
    if (error || !user) {
      return res.status(401).json({ error:'Utilisateur non trouvé' });
    }

    if (user.password_changed_at) {
      const pwdChangedAtSec = Math.floor(new Date(user.password_changed_at).getTime() / 1000);
      const tokenIat = decoded.iat || 0;
      if (tokenIat < pwdChangedAtSec) {
        return res.status(401).json({ error: 'Token expiré (mot de passe modifié)' });
      }
    }

    req.user = user;
    req.authMethod = 'jwt';
    next();
  }
  
const permission = (permission) => {
  return (req, res, next) => {
    if (!req.user.roles[permission]) {
      return res.status(403).json({ error:'Permission refusée'});
    }
    next();
  };
};


app.post('/login', authenticate, permission('can_post_login'), async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  }

  const last = loginAttempts.get(email);
  const now = Date.now();
  if (last && (now - last) < 5000) {
    const waitSec = Math.ceil((5000 - (now - last)) / 1000);
    return res.status(429).json({ error: `Trop de tentatives. Réessayer dans ${waitSec} seconde(s).` });
  }

  loginAttempts.set(email, now);

  const { data: user, error } = await supabase
    .from('users')
    .select('*, roles(*)')
    .eq('email', email)
    .single();

  if (error || !user) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }
  const token = jwt.sign({ userId: user.id }, jwt_secret, { expiresIn: '1h' });

  res.json({
    message: 'Connexion réussie',
    user: {
      id: user.id,
      nom: user.nom,
      email: user.email,
      role: user.roles.nom
    },
    token
  });
});

app.post('/change-password', authenticate, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Ancien et nouveau mot de passe requis' });
  }

  const user = req.user;
  const match = await bcrypt.compare(oldPassword, user.password);
  if (!match) {
    return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
  }

  const hashed = await bcrypt.hash(newPassword, 10);
  const { data, error } = await supabase
    .from('users')
    .update({
      password: hashed,
      password_changed_at: new Date().toISOString()
    })
    .eq('id', user.id)
    .select()
    .single();

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  const token = jwt.sign(
    {userId: user.id }, 
    jwt_secret,
    {expiresIn: '1h'}
  );

  res.json({ message: 'Mot de passe changé avec succès', token});
});

app.get('/my-user', authenticate, permission('can_get_my_user'), async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user.id,
        nom: req.user.nom,
        email: req.user.email,
        role: req.user.roles.nom
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/users', authenticate, permission('can_get_users'), async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, nom, email, roles(nom)');

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    res.json({ users });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// -- Partie 4 ----------------------

app.post('/products', authenticate, permission('can_post_products'), async (req, res) => {
  try {
    const { nom, prix } = req.body;

    if (!nom || !prix) {
      return res.status(400).json({ error: 'Nom et prix requis' });
    }

    const shopifyProduct = {
      product: {
        title: nom,
        body_html: "<p>Description du produit</p>",
        vendor: "Leekid",
        product_type: "",
        status: "active",
        variants: [
          {
            price: prix.toString(),
            inventory_quantity: 1,
            inventory_management: "shopify"
          }
        ]
      }
    };

    if (!shopify_url || !shopify_access_token) {
      return res.status(500).json({ error: 'Configuration Shopify manquante' });
    }

    const shopifyResponse = await axios.post(
      `${shopify_url}/admin/api/2025-01/products.json`,
      shopifyProduct,
      {
        headers: {
          'X-Shopify-Access-Token': shopify_access_token,
          'Content-Type': 'application/json'
        },
        timeout: 5000
      }
    );

    const createdProduct = shopifyResponse.data?.product;
    if (!createdProduct?.id) {
      throw new Error('Réponse Shopify invalide');
    }

    const shopifyId = createdProduct.id;


    const { data: product, error: dbError } = await supabase
      .from('products')
      .insert([
        {
          shopify_id: shopifyId.toString(),
          nom,
          prix,
          created_by: req.user.id,
          sales_count: 0
        }
      ])
      .select()
      .single();

    if (dbError) {
      console.error('Erreur Supabase:', dbError.message);
      return res.status(500).json({ error: dbError.message });
    }

    res.status(201).json({
      message: 'Produit créé avec succès',
      product: {
        id: product.id,
        shopify_id: product.shopify_id,
        nom: product.nom,
        prix: product.prix
      }
    });
  } catch (error) {
    console.error('Erreur globale:', error.message);

    if (error.response) {
      return res.status(error.response.status || 500).json({
        error: 'Erreur Shopify',
        details: error.response.data
      });
    }

    res.status(500).json({ error: error.message });
  }
});

app.get('/my-products', authenticate, async (req, res) => {
  try {
    const { data: products, error } = await supabase
      .from('products')
      .select('*')
      .eq('created_by', req.user.id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ error: error.message });
    }
    res.json({ 
      count: products.length,
      products 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/products', authenticate, async (req, res) => {
  try {
    const { data: products, error } = await supabase
      .from('products')
      .select(`
        *,
        users:created_by (
          id,
          nom,
          email
        )
      `)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    res.json({ 
      count: products.length,
      products 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// -- Partie 5 ------------------------------

app.post('/api-keys', authenticate, async (req, res) => {
  try {
    if (req.authMethod !== 'jwt') {
      return res.status(403).json({ error: 'Gestion des clés via token utilisateur requis' });
    }
    const { nom_cle } = req.body;
    if (!nom_cle) return res.status(400).json({ error: 'Nom de la clé requis' });

    const { data: exists } = await supabase
      .from('api_keys')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('nom_cle', nom_cle)
      .single();

    if (exists) return res.status(400).json({ error: 'Nom de la clé déjà utilisé' });

    const rawKey = crypto.randomBytes(32).toString('hex');
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

    const { data: newKey, error } = await supabase
    .from('api_keys')
    .insert([{
        user_id: req.user.id,
        nom_cle: nom_cle,
        api_key: keyHash,
        last_used_at: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }
    ])
    .select()
    .single();

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    res.status(201).json({
      message: 'Clé API créée',
      api_key: {
        id: newKey.id,
        nom_cle: newKey.nom_cle,
        created_at: newKey.created_at,
        key: rawKey
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api-keys', authenticate, async (req, res) => {
  try {
    if (req.authMethod !== 'jwt') {
      return res.status(403).json({ error: 'Utiliser un token utilisateur pour lister les clés API' });
    }

   const { data: keys, error } = await supabase
    .from('api_keys')
    .select('id, nom_cle, created_at')
    .eq('user_id', req.user.id);

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    res.json({ keys });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api-keys/:id', authenticate, async (req, res) => {
  try {
    if (req.authMethod !== 'jwt') {
      return res.status(403).json({ error: 'Utiliser un token utilisateur pour supprimer une clé API' });
    }

    const keyId = req.params.id;
    const { data: existing, error: exErr } = await supabase
      .from('api_keys')
      .select('*')
      .eq('id', keyId)
      .eq('user_id', req.user.id)
      .single();

    if (exErr || !existing) {
      return res.status(404).json({ error: 'Clé API introuvable' });
    }
    
    const { error } = await supabase
      .from('api_keys')
      .delete()
      .eq('id', keyId)
      .eq('user_id', req.user.id);

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    res.json({ message: 'Clé API supprimée' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// -- Partie 6 ----------------------------------------- 

app.post('/webhooks/shopify-sales', express.raw({ type: 'application/json' }), async (req, res) => {

});



// -- Partie 7 --------------------------------------------------

app.get('/my-bestsellers', authenticate, async (req, res) => {
  try {
    if (!req.user.roles || req.user.roles.role_id !== "6e46bd58-b5fd-4062-8ae7-84329ae67dc9") {
      return res.status(403).json({ error: 'Fonction réservée aux utilisateurs PREMIUM' });
    }

    const { data: products, error } = await supabase
      .from('products')
      .select('*')
      .eq('created_by', req.user.id)
      .order('sales_count', { ascending: false })

    if (error) return res.status(500).json({ error: error.message });

    res.json({ count: products.length, bestsellers: products });
  }
  catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.listen(3000, () => {
  console.log(`Serveur démarré sur le port 3000`);
});

export default app;