require('./src/services').load(__dirname + '/parameters.json', function(container) {
    container.get('app').listen(container.get('app_port'));
});