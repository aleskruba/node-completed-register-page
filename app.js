const express = require('express');
const mongoose = require('mongoose');
const authRoutes =require('./routes/authRoutes')
const cookieParser = require('cookie-parser');
const { checkUser,requireAuth} = require('./middleware/authMiddleware');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000


// middleware
app.use(express.static('public'));

app.use(express.json());

app.use(cookieParser());

const USER = process.env.USER
const PASSWORD = process.env.PASSWORD

const dbURI = `mongodb+srv://${USER}:${PASSWORD}@cluster0.ax6wn83.mongodb.net/?retryWrites=true&w=majority`

mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true})
  .then((result) => app.listen(PORT,()=>console.log(`listen on port ${PORT}`)))
  .catch((err) => console.log(err));


app.set('view engine', 'ejs');

app.get('*',checkUser);
app.get('/', (req, res) => res.render('home'));


app.use(authRoutes)