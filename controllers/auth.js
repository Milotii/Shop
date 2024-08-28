exports.getLogin = (req, res, next) => {
    const isLoggedIn = (req
        .get('Cookie')
        .match(/loggedIn=(true|false)/)[1]); // Extract and log 'true' or 'false'
            res.render('auth/login', { 
        path: '/login',
        pageTitle: 'Login',
        isAuthenticated: isLoggedIn
    });
    };

exports.postLogin = (req, res, next) => {
    res.setHeader('Set-Cookie', 'loggedIn=true'); 
    res.redirect('/');
};