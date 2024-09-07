const path = require('path');

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const csrf = require('csurf');
const flash = require('connect-flash');
const multer = require('multer');

const User = require('./models/user');

const MONGODB_URI = 'mongodb+srv://miloti:FJ5jFkrOnJ6fuOyE@cluster0.9d7nr.mongodb.net/shop?retryWrites=true&w=majority&appName=Cluster0';

const app = express();
const store = new MongoDBStore({
    uri: MONGODB_URI,
    collection: 'sessions'
});

const csrfProtection = csrf();

const fileStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'images');
    },
    filename: (req, file, cb) => {
        const date = new Date();
        const formattedDate = date.getFullYear() + '-' + (date.getMonth() + 1) + '-' + date.getDate();
        cb(null, formattedDate + '-' + file.originalname);
    }
});


const fileFilter = (req, file, cb) => {
    if(file.mimetype === 'image/png' || 
        file.mimetype === 'image/jpg' || 
        file.mimetype === 'image/jpeg') {
    cb(null, true);
} else {
    cb(null, false);
}
};

const errorController = require('./controllers/error')

app.set('view engine', 'ejs');
app.set('views', 'views');

const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const authRoutes = require('./routes/auth');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(multer({storage: fileStorage, fileFilter: fileFilter}).single('image'));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use(session({
    secret: 'my secret',
    resave: false,
    saveUninitialized: false,
    store: store
})
); 
app.use(csrfProtection);
app.use(flash());

app.use((req, res, next) => {
    if (!req.session) {
        return next(); // Skip to the next middleware if session is missing
    }
    res.locals.isAuthenticated = req.session.isLoggedIn || false;
    res.locals.csrfToken = req.csrfToken();
    next();
});


app.use((req, res, next) => {
    if (!req.session.user) {
        return next(); // Return to prevent further execution
    }
    User.findById(req.session.user._id)
    .then(user => {
        if (!user) {
            return next(); // If the user is not found, skip to the next middleware
        }
        req.user = user;
        next();
    })
    .catch(err => {
        next(new Error(err));
         // Ensure errors are properly handled
    });
});


app.use('/admin', adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

app.get('/500', errorController.get500);

app.use(errorController.get404);

app.use((error, req, res, next) => {
    console.log(error);
    res.status(500).render('500', {
        pageTitle: 'Error!',
        path: '/500',
        isAuthenticated: req.session ? req.session.isLoggedIn : false
    });
});


mongoose
.connect(MONGODB_URI)
.then(result => {
    console.log('Connected');
    app.listen(3000);
})
.catch(err => {
    console.log(err);
});