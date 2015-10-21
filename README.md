# Feide Connect API Gatekeeper Expressjs Middleware

Install FeideConnectAPI using npm:

	npm install feideconnectapi --save

Then include it in your ExpressJS server application:


	var FeideConnectAPI = require('feideconnectapi').FeideConnectAPI;


Register your API at Connect Dashboard:

* <https://dashboard.feideconnect.no>

Point your API endpoint in Dashboard to your ExpressJS API.

And initialize FeideConnectAPI using the password that was generated for trust between Feide Connect API Gatekeeper and your ExpressJS API:

```javascript
	var fc = new FeideConnectAPI({
	    "password": "30d63d9b-3574-4832-be37-0c93121fca21"
	});
```

FeideConnectAPI comes with several middlewares. First the optional `cors()` middleware, and then the important `setup()` middleware that establish trust and parses the incoming request headers.

A typical use is this:

	app.use('/api', fc.cors(), fc.setup(), router);


Within a request handler, you may access some information:

```javascript
	var router = express.Router();
	router.get('/', function(req, res) {
	    res.json({ 
	        "message": 'hooray! welcome to our api!',
	        "youMustBe": req.feideconnect.userid,
	        "accessingUsingThisClient": req.feideconnect.clientid,
	        "withTheseSubScopes": req.feideconnect.scopes
	    });
	});
```


You may easily use the `policy()` middleware to apply some kind of authorization policy before the request is dealt with.

```javascript
	router.get('/write', fc.policy({requireScopes: ["write"], requireUserUnlessScopes: ["clientonly"]}), function(req, res) {
	    res.json({ 
	        message: 'This endpoint is slightly more protected',
	        "youMustBe": req.feideconnect.userid,
	        "usingClient": req.feideconnect.clientid
	    });
	});
```

The `policy()` middleware takes an object as input and the object properties can be one of:

* `requireUser` - does not accept requests that is not on behalf of an authenticated user
* `requireUserUnlessScopes` - does not accept requests that is not on behalf of an authenticated user, unless the request is authorized with a set of one or more specific scopes.
* `requireScopes` - does not accept requests without this subscope.


A simpler example:

```javascript
	router.get('/', fc.policy({requireUser: true}), function(req, res) {
	    res.json({ 
	        message: 'hooray! welcome to our api!',
	        "youMustBe": req.feideconnect.userid
	    });
	});
```
