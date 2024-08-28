const path = require('path');

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const User = require('./models/user');

const app = express();
const errorController = require('./controllers/error')

app.set('view engine', 'ejs');
app.set('views', 'views');

const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const authRoutes = require('./routes/auth');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use ((req, res, next ) => {
    User.findById('66cd1b8ff1da4b31ca1435f2')
    .then(user => {
        req.user = user;
        next();
    })
    .catch(err => {
        console.log(err);
    });
});

app.use('/admin', adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

app.use(errorController.get404);

mongoose.connect('mongodb+srv://miloti:FJ5jFkrOnJ6fuOyE@cluster0.9d7nr.mongodb.net/shop?retryWrites=true&w=majority&appName=Cluster0')
.then(result => {
    User.findOne().then(user => {
        if(!user) {
            const user = new User ({
                name: 'Miloti',
                email: 'miloti@gmail.com',
                cart: {
                    items: []
                }
            });
            user.save();
        }
    })
    console.log('Connected');
    app.listen(3000);
})
.catch(err => {
    console.log(err);
});