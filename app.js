const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const { v4: uuidv4 } = require('uuid');

app.use(express.json());

// Base de données factice pour stocker les données
let users = [];

// Middleware pour vérifier l'authentification
const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
      return res.status(401).json({ message: 'Authentification requise.'});
    }
  
    jwt.verify(token, 'secret', (err, user) => {
      if (err) {
        return res.status(403).json({ message: 'Token invalide.' });
      }
      req.user = user;
      next();
    });
  };

// Route pour l'inscription (création d'un compte)
app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  // Vérifier si l'utilisateur existe déjà
  const existingUser = users.find(user => user.username === username);
  if (existingUser) {
    return res.status(400).json({ message: 'Ce nom d\'utilisateur est déjà utilisé.' });
  }

  // Générer un sel et hasher le mot de passe
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, (err, hash) => {
      if (err) throw err;
      const newUser = { username, password: hash , id: uuidv4() };
      users.push(newUser);
      res.status(201).json({ message: 'Utilisateur créé avec succès.' });
    });
  });
});

// Route pour la connexion
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Vérifier si l'utilisateur existe
  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect.' });
  }

  // Comparer le mot de passe haché
  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) throw err;
    if (isMatch) {
      // Créer un token JWT
      const token = jwt.sign({ username }, 'secret', { expiresIn: '1h' });
      res.json({ token });
    } else {
      res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect.' });
    }
  });
  console.log(users);
});

// Routes nécessitant une authentification

// Route pour récupérer tous les utilisateurs (GET)
app.get('/users', (req, res) => {
  res.json(users);
});

// Route pour récupérer un utilisateur par son ID (GET)
app.get('/users/:id',  (req, res) => {
  const user = users.find(user => user.id === req.params.id);
  if (!user) {
    return res.status(404).json({ message: 'Utilisateur non trouvé.' });
  }
  res.json(user);
});

// Route pour créer un nouvel utilisateur (POST)
app.post('/users',  (req, res) => {
  const { username, password } = req.body;
  const newUser = { username, password };
  users.push(newUser);
  res.status(201).json(newUser);
});

// Route pour mettre à jour un utilisateur (PUT)
app.put('/users/:id',  (req, res) => {
  const user = users.find(user => user.id === req.params.id);
  if (!user) {
    return res.status(404).json({ message: 'Utilisateur non trouvé.' });
  }
  user.username = req.body.username;
  user.password = req.body.password;
  res.json(user);
});

// Route pour supprimer un utilisateur (DELETE)
app.delete('/users/:id',  (req, res) => {
  const index = users.findIndex(user => user.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ message: 'Utilisateur non trouvé.' });
  }
  const deletedUser = users.splice(index, 1);
  res.json(deletedUser[0]);
});

module.exports = app;