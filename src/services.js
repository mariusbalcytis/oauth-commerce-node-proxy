var ServiceContainer = require('lib/serviceContainer'), container = new ServiceContainer();
module.exports = container
    .set({
        'token_signer_secret': '',
        'header_signer_secret': '',
        'secret_crypto.password': '',
        'secret_crypto.algorithm': 'AES-256-CBC',
        'app_trust_proxy': false,
        'app_port': 3000,
        'client_secret_size': 30,
        'application_secret_size': 30,
        'application_credentials_algorithm': 'hmac-sha-256',
        'static_credentials': {}
    })

    .set('redis_client', function() {
//        var client = require("redis").createClient(), util = require("util");
//        client.monitor();
//        client.on("monitor", function (time, args) {
//            console.log(time + ": " + util.inspect(args));
//        });

        return require("redis").createClient();
    })
    .set('token_signer', function() {
        var Signer = require("lib/hmacSigner");
        return new Signer(this.get('token_signer_secret'), 'sha256');
    })
    .set('header_signer', function() {
        var Signer = require("lib/hmacSigner");
        return new Signer(this.get('header_signer_secret'), 'sha256');
    })
    .set('secret_crypto', function() {
        var Crypto = require("lib/crypto");
        return new Crypto(this.get('secret_crypto.algorithm'), this.get('secret_crypto.password'));
    })

    .set('repository.code', function() {
        var CodeRepository = require("repository/signed/code");
        var CounterRepository = require("repository/redis/counter");
        var counter = new CounterRepository(this.get('redis_client'), 'code:counter');
        return new CodeRepository(this.get('token_signer'), counter);
    })
    .set('repository.access_token', function() {
        var TokenRepository = require("repository/signed/token");
        return new TokenRepository(this.get('token_signer'));
    })
    .set('repository.blacklist', function() {
        var BlacklistRepository = require("repository/redis/blacklist");
        return new BlacklistRepository(this.get('redis_client'));
    })
    .set('repository.client_credentials', function() {
        var Repository = require("repository/redis/credentialsExtended");
        var models = require('model/models');
        var repository = new Repository(
            this.get('redis_client'),
            this.get('secret_crypto'),
            'client',
            models.ClientCredentials,
            models.ClientCredentialsCollection
        );
        repository.setModelType('client');
        return repository;
    })
    .set('repository.application_credentials', function() {
        var Repository = require("repository/redis/credentialsExtended");
        var models = require('model/models');
        var repository = new Repository(
            this.get('redis_client'),
            this.get('secret_crypto'),
            'client',
            models.ApplicationCredentials,
            models.ApplicationCredentialsCollection
        );
        repository.setModelType('application');
        return repository;
    })
    .set('repository.login_credentials.redis', function() {
        var Repository = require("repository/redis/credentials");
        var models = require('model/models');
        return new Repository(
            this.get('redis_client'),
            this.get('secret_crypto'),
            'client',
            models.LoginCredentials,
            models.LoginCredentialsCollection
        );
    })
    .set('repository.application_password', function() {
        var Repository = require("repository/redis/credentialsExtended");
        var models = require('model/models');
        return new Repository(
            this.get('redis_client'),
            this.get('secret_crypto'),
            'app',
            models.ApplicationPassword,
            models.ApplicationPasswordCollection
        );
    })
    .set('repository.client_credentials.memory', function() {
        var Repository = require("repository/memory/credentials");
        return new Repository(this.get('static_credentials'));
    })
    .set('repository.login_credentials', function() {
        var Repository = require("repository/fallback");
        return new Repository({
            'load': [
                this.get('repository.client_credentials.memory')
            ]
        }, this.get('repository.login_credentials.redis'));
    })
    .set('repository.timestamp', function() {
        var TimestampRepository = require("repository/redis/timestamp");
        return new TimestampRepository(this.get('redis_client'));
    })

    .set('middleware.auth', function() {
        return require("middleware/auth")(this.get('mac_validator'));
    })
    .set('middleware.body', function() {
        return require("middleware/body")();
    })
    .set('middleware.permissions', function() {
        return require("middleware/permissions");
    })
    .set('middleware.once', function() {
        return require("middleware/once");
    })

    .set('mac_parser', function() {
        return require("lib/mac/parser");
    })
    .set('mac_validator', function() {
        var Validator = require("lib/mac/validator");
        return new Validator(
            this.get('signer_registry'),
            this.get('repository.timestamp'),
            this.get('repository.blacklist'),
            this.get('repository.access_token'),
            this.get('repository.login_credentials')
        );
    })

    .set('random', function() {
        return require("lib/random");
    })

    .set('app', function() {
        var express = require("express");
        return express()
            .set('case sensitive routing', true)
            .set('strict routing', true)
            .set('trust proxy', this.get('app_trust_proxy'));
    })
    .after('app', function(app) {
        app.use(require('connect-powered-by')(null));
    })
    .after('app', function(app) {
        var auth = this.get('middleware.auth');
        var permissions = this.get('middleware.permissions');
        var once = this.get('middleware.once');
        var body = this.get('middleware.body');
        var json = require('express').json();
        var urlEncoded = require('express').urlencoded();
        app
            .post('/api/auth/v1/token', once(urlEncoded, body), auth, permissions(), controllerAction('auth', 'createToken'))
            .post('/api/auth/v1/client', urlEncoded, controllerAction('auth', 'createClient'))
            .delete('/api/auth/v1/client', body, auth, permissions(), controllerAction('auth', 'removeClient'))

            .get(
                '/api/internal/v1/credentials/:id',
                body, auth, permissions(['internal_api']),
                controllerAction('internal', 'getClientCredentials')
            )
            .get(
                '/api/internal/v1/credentials',
                body, auth, permissions(['internal_api']),
                controllerAction('internal', 'getAllCredentialsForClient')
            )
            .post(
                '/api/internal/v1/credentials',
                once(json, body), auth, permissions(['internal_api']),
                controllerAction('internal', 'createClientCredentials')
            )
            .delete(
                '/api/internal/v1/credentials/:id',
                body, auth, permissions(['internal_api']),
                controllerAction('internal', 'removeClientCredentials')
            )
            .delete(
                '/api/internal/v1/credentials',
                body, auth, permissions(['internal_api']),
                controllerAction('internal', 'removeAllCredentialsForClient')
            )

            .get(
                '/api/internal/v1/application/:id',
                body, auth, permissions(['internal_api']),
                controllerAction('internal', 'getApplicationPassword')
            )
            .get(
                '/api/internal/v1/application',
                body, auth, permissions(['internal_api']),
                controllerAction('internal', 'getAllPasswordsForApplication')
            )
            .post(
                '/api/internal/v1/application',
                once(json, body), auth, permissions(['internal_api']),
                controllerAction('internal', 'createApplicationPassword')
            )
            .delete(
                '/api/internal/v1/application/:id',
                body, auth, permissions(['internal_api']),
                controllerAction('internal', 'removeApplicationPassword')
            )
            .delete(
                '/api/internal/v1/application',
                body, auth, permissions(['internal_api']),
                controllerAction('internal', 'removeAllPasswordsForApplication')
            )

            .post(
                '/api/internal/v1/code',
                once(json, body), auth, permissions(['internal_api']),
                controllerAction('internal', 'createCode')
            )

            .all('*', body, auth, controllerAction('proxy', 'proxy'))
        ;

    })
    .after('app', function(app) {
        var errors = require('lib/errors');

        app.use(function(err, req, res, next) {
            console.log('error', err);
            console.error(err.stack);
            if (err instanceof errors.ApiError) {
                res.send(err.statusCode ? err.statusCode : 400, JSON.stringify({
                    'error': err.errorCode ? err.errorCode : err.message,
                    'error_description': err.errorDescription ? err.errorDescription : err.message,
                    'error_uri': err.errorUri ? err.errorUri : null
                }));
            }
            res.send(500, JSON.stringify({
                'error': err.message
            }));
        });
        app.use(function(req, res, next){
            res.send(404, JSON.stringify({
                'error': 'not_found',
                'error_description': 'Cannot find path specified'
            }));
        });
    })

    .set('controller.auth', controllerDefinition('auth'))
    .set('controller.internal', controllerDefinition('internal', function() {
        return [container.get('signer_registry')];
    }))
    .set('controller.proxy', controllerDefinition('proxy', function() {
        return [container.get('header_signer')];
    }))

    .set('signer_registry', function() {
        var SignerRegistry = require('lib/signer/registry');
        return new SignerRegistry();
    })
    .after('signer_registry', function(registry) {
        var HmacSigner = require('lib/signer/hmac');
        var RsaSigner = require('lib/signer/rsa');

        var random = this.get('random');
        var randomStringSize = this.get('client_secret_size');
        var generateRandom = function(callback) {
            random.generateRandomString(randomStringSize, callback);
        };

        registry.add(new HmacSigner('sha256', generateRandom));
        registry.add(new HmacSigner('sha512', generateRandom));
        registry.add(new RsaSigner('sha256', 'pkcs1'));
        registry.add(new RsaSigner('sha512', 'pkcs1'));
    })
;

function controllerDefinition(controller, argumentsProvider) {
    return function() {
        var container = this, Controller = require('controller/' + controller);
        Controller.prototype.get = function(serviceId) {
            return container.get(serviceId);
        };
        if (argumentsProvider) {
            var obj = Object.create(Controller.prototype);
            Controller.apply(obj, argumentsProvider());
            return obj;
        } else {
            return new Controller();
        }
    };
}
function controllerAction(controller, action) {
    return function(res, req, next) {
        var object = container.get('controller.' + controller);
        try {
            object[action].apply(object, arguments);
        } catch (e) {
            next(e);
        }
    };
}