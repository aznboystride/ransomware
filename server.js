var express = require('express');
var httpApp = express();
var httpsApp = express();
var http = require('http');
var https = require('https');
var fs = require('fs');
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');

var helmet = require('helmet');
var ONE_YEAR = 31536000000;

httpsApp.use(helmet.hsts({
        maxAge: ONE_YEAR,
        includeSubdomains: true,
        force: true
}));

httpsApp.use(bodyParser());

var key_pairs = [

];

var cipher = [
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-CBC-SHA384',
        'ECDHE-RSA-AES256-CBC-SHA256',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'DHE-RSA-AES128-GCM-SHA256',
        'DHE-RSA-AES256-GCM-SHA384',
        '!aNULL',
        '!MD5',
        '!DSS'
].join(':');

httpApp.get("*", function(req, res, next){
        res.redirect('https://' + req.headers.host + req.url);
});

httpsApp.get('/', function(req, res){
        res.send('You are in the right place.');
});

httpsApp.post('/api/retrieve/', verifyToken, (req, res) => {
    jwt.verify(req.token, 'secret key', (err, authData) => {
            if (err) {
                    res.sendStatus(403)
            }
            else {
                var publicKey = req.body.publicKey
                for(var i = 0; i < key_pairs.length; i++) {
                    if (key_pairs[i]['publicKey'] == publicKey) {
                        res.send(key_pairs[i]['privateKey'])
                        return
                    }
                }
                res.send("Does not exists")
            }
    })
})

httpsApp.get('/api/keys', verifyToken, (req, res) => {
    jwt.verify(req.token, 'secret key', (err, authData) => {
        if (err) {
            res.sendStatus(403)
        }
        else
        {
            res.send(key_pairs)
        }
    })
})

httpsApp.post('/api/post/', verifyToken, (req, res) => {
    jwt.verify(req.token, 'secret key', (err, authData) => {
        if (err) {
           res.sendStatus(403)
        }
        else {
            var publicKey = req.body.publicKey
            var privateKey = req.body.privateKey
	        for(var i = 0; i < key_pairs.length; i++) {
                if (key_pairs[i]['publicKey'] == publicKey) {
                    res.send("Public Key is already in database")
                    return
                }

            }
            key_pairs.push({'publicKey' : publicKey, 'privateKey' : privateKey})
		    res.send("Inserted: " + publicKey)
        }
    })
})

var options = {
        key: fs.readFileSync('/etc/letsencrypt/live/fairmichael.me/privkey.pem'),
        cert: fs.readFileSync('/etc/letsencrypt/live/fairmichael.me/fullchain.pem'),
        ciphers: cipher
};

function verifyToken(req, res, next) {
    
    const bearerHeader = req.headers['authorization'];

    if(typeof bearerHeader !== 'undefined')
    {
        const bearer = bearerHeader.split(' ');

        const token = bearer[1];

        req.token = token;

        next();
    } else {
        res.sendStatus(403);
    }
}

http.createServer(httpApp).listen(80);
https.createServer(options, httpsApp).listen(443);
console.log("Listening");
