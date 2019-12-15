fs = require('fs');
glob = require("glob")
dateFormat = require('dateformat');
var app = require('express')();
var http = require('http').Server(app);
http_resolver = require('http')
https_resolver = require('https')
var io = require('socket.io')(http);
var dns = require('dns');
var axfr = require('dns-axfr');
//CIDR parser
netmask = require('netmask').Netmask
//headless chrome stuff
const chromeLauncher = require('chrome-launcher');
const CDP = require('chrome-remote-interface');
//port scanner
evilscan = require('evilscan');
//ping sweeps
var ping = require('ping');

app.get('/', function(req, res){
  res.sendFile(__dirname + '/scopecreep.html');
});

app.get('/favicon.ico', function(req, res){
  res.sendFile(__dirname + '/images/favicon.ico');
});

app.get('/scripts/jquery.min.js', function(req, res){
  res.sendFile(__dirname + '/scripts/jquery.min.js');
});

app.get('/scripts/jquery.cookie.js', function(req, res){
  res.sendFile(__dirname + '/scripts/jquery.cookie.js');
});

app.get('/scripts/vivagraph.min.js', function(req, res){
  res.sendFile(__dirname + '/scripts/vivagraph.min.js');
});

app.get('/scripts/socket.io.js', function(req, res){
  res.sendFile(__dirname + '/scripts/socket.io.js');
});

app.get('/images/network', function(req, res){
  res.sendFile(__dirname + '/images/network.svg');
});

app.get('/images/mail', function(req, res){
  res.sendFile(__dirname + '/images/mail.svg');
});

app.get('/images/server', function(req, res){
  res.sendFile(__dirname + '/images/server.svg');
});

app.get('/images/subdomain', function(req, res){
  res.sendFile(__dirname + '/images/subdomain.svg');
});

app.get('/images/txt', function(req, res){
  res.sendFile(__dirname + '/images/txt.svg');
});

app.get('/images/organization', function(req, res){
  res.sendFile(__dirname + '/images/organization.svg');
});

app.get('/images/cidr', function(req, res){
  res.sendFile(__dirname + '/images/cidr.svg');
});

app.get('/images/person', function(req, res){
  res.sendFile(__dirname + '/images/person.svg');
});

app.get('/images/linkedin', function(req, res){
  res.sendFile(__dirname + '/images/linkedin.svg');
});

app.get('/images/position', function(req, res){
  res.sendFile(__dirname + '/images/position.svg');
});

app.get('/images/nameserver', function(req, res){
  res.sendFile(__dirname + '/images/nameserver.svg');
});

app.get('/images/port', function(req, res){
  res.sendFile(__dirname + '/images/port.svg');
});

app.get('/images/email', function(req, res){
  res.sendFile(__dirname + '/images/email.svg');
});

app.get('/images/info', function(req, res){
  res.sendFile(__dirname + '/images/info.svg');
});

app.get('/images/location', function(req, res){
  res.sendFile(__dirname + '/images/location.svg');
});

app.get('/images/phone', function(req, res){
  res.sendFile(__dirname + '/images/phone.svg');
});

io.on('connection', function(socket){
  socket.on('whois_lookup', function(query){
    var whois = require('whois')
    whois.lookup(query, function(err, data) {
      var searches = [
        {"search_string": "CIDR:", "node_type": "cidr"},
        {"search_string": "NetRange:", "node_type": "info"},
        {"search_string": "Organization:", "node_type": "organization"},
        {"search_string": "OrgTechEmail:", "node_type": "email"},
        {"search_string": "OrgName:", "node_type": "organization"}
      ]
      for(i=0; i < searches.length; i++){
        myRegexp = new RegExp(`^${searches[i].search_string}.+$`,"gm");
        do {
          match = myRegexp.exec(data);
          if (match) {
            new_node = JSON.parse('{"id": "'+ match[0].replace(/ /g,'').split(':')[1] + '", "parent": "' + query + '", "node_type": "' + searches[i].node_type +'"}')
            io.emit('add_node', new_node)
          }
        } while (match);
      }
    })
  });

  socket.on('whoxy_api_check', function(query_object){

    api_call = 'https://api.whoxy.com/?key=' + query_object + '&account=balance'

    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        try{
          results = JSON.parse(data)
          io.emit('server_message', "Available Balance: " + results.reverse_whois_balance)
        }catch (err){
          io.emit('server_message', "There is a problem with your API key")
        }
      });
    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('whoxy_search', function(query_object){

    if(query_object.search_method == 'email'){
      api_call = 'https://api.whoxy.com/?key=' + query_object.whoxy_api_key + '&reverse=whois&email=' + query_object.node_id + '&page=' + query_object.page_number
    }else if(query_object.search_method == 'keyword'){
      api_call = 'https://api.whoxy.com/?key=' + query_object.whoxy_api_key + '&reverse=whois&keyword=' + query_object.node_id + '&page=' + query_object.page_number
    }else{
      api_call = 'https://api.whoxy.com/?key=' + query_object.whoxy_api_key + '&reverse=whois&company=' + query_object.node_id + '&page=' + query_object.page_number
    }

    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data)
        if(results.total_pages > 1){
          io.emit('server_message', "Total Pages: " + results.total_pages)
        }
        for(i=0; i < results.search_result.length; i++){
          record = results.search_result[i]
          new_node = JSON.parse('{"id": "'+ record.domain_name + '", "parent": "' + query_object.node_id + '", "node_type": "network"}')
          io.emit('add_node', new_node)
          if(record.registrant_contact.company_name){
            new_node = JSON.parse('{"id": "'+ record.registrant_contact.company_name + '", "parent": "' + record.domain_name  + '", "node_type": "organization"}')
            io.emit('add_node', new_node)
          }
          if(record.administrative_contact.company_name){
            new_node = JSON.parse('{"id": "'+ record.registrant_contact.company_name + '", "parent": "' + record.domain_name  + '", "node_type": "organization"}')
            io.emit('add_node', new_node)
          }
          if(record.technical_contact.company_name){
            new_node = JSON.parse('{"id": "'+ record.registrant_contact.company_name + '", "parent": "' + record.domain_name  + '", "node_type": "organization"}')
            io.emit('add_node', new_node)
          }
          if(record.registrant_contact.email_address){
            new_node = JSON.parse('{"id": "'+ record.registrant_contact.email_address + '", "parent": "' + record.domain_name  + '", "node_type": "email"}')
            io.emit('add_node', new_node)
            if(record.registrant_contact.phone_number){
              new_node = JSON.parse('{"id": "'+ record.registrant_contact.phone_number + '", "parent": "' + record.registrant_contact.email_address + '", "node_type": "phone"}')
              io.emit('add_node', new_node)
            }
          }
          if(record.administrative_contact.email_address){
            new_node = JSON.parse('{"id": "'+ record.administrative_contact.email_address + '", "parent": "' + record.domain_name  + '", "node_type": "email"}')
            io.emit('add_node', new_node)
            if(record.administrative_contact.phone_number){
              new_node = JSON.parse('{"id": "'+ record.administrative_contact.phone_number + '", "parent": "' + record.administrative_contact.email_address + '", "node_type": "phone"}')
              io.emit('add_node', new_node)
            }
          }
          if(record.technical_contact.email_address){
            new_node = JSON.parse('{"id": "'+ record.technical_contact.email_address + '", "parent": "' + record.domain_name  + '", "node_type": "email"}')
            io.emit('add_node', new_node)
            if(record.technical_contact.phone_number){
              new_node = JSON.parse('{"id": "'+ record.technical_contact.phone_number + '", "parent": "' + record.technical_contact.email_address  + '", "node_type": "phone"}')
              io.emit('add_node', new_node)
            }
          }
        }
      });
    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });


  socket.on('mx_query', function(query){
    dns.resolveMx(query, function(err, addresses){
      for (server in addresses){
        new_node = JSON.parse('{"id": "'+ addresses[server].exchange + '", "parent": "' + query + '", "node_type": "mail"}')
        io.emit('add_node', new_node)
      }
    })
  });

  socket.on('reverse_lookup', function(query_object){
    //run a reverse lookup on everything in the range if it's a CIDR subnet
    if(query_object.node_type == "cidr"){
       var block = new netmask(query_object.node_id);
       block.forEach(function(ip){
         dns.reverse(ip.toString(), function(err, addresses){
          for (server in addresses){
            if(addresses[server].split('.').length == 2){
              new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + query_object.node_id + '", "node_type": "network"}')
            }else{
              new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + query_object.node_id + '", "node_type": "subdomain"}')
            }
            io.emit('add_node', new_node)
          }
        })
      });
    //otherwise treat like a single query
    }else{
      dns.reverse(query_object.node_id, function(err, addresses){
        for (server in addresses){
          if(addresses[server].split('.').length == 2){
            new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + query_object.node_id + '", "node_type": "network"}')
          }else{
            new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + query_object.node_id + '", "node_type": "subdomain"}')
          }
          io.emit('add_node', new_node)
        }
      })
    }
  });

  socket.on('txt_records', function(query){
    dns.resolveTxt(query, function(err, records){
      for (entry in records){
        new_node = JSON.parse('{"id": "'+ records[entry][0] + '", "parent": "' + query + '", "node_type": "txt"}')
        io.emit('add_node', new_node)
        if(records[entry][0].indexOf('v=spf') !== -1){
          myRegexp = /ip4:(\d+\.\d+\.\d+\.\d+([^\s]+))/g
          do {
            match = myRegexp.exec(records[entry]);
            if (match) {
              if(match[1].indexOf('/') !== -1){
                new_node = JSON.parse('{"id": "'+ match[1] + '", "parent": "' + records[entry][0] + '", "node_type": "cidr"}')
              }else if(match[1].indexOf('-') !== -1){
                new_node = JSON.parse('{"id": "Net Range: '+ match[1] + '", "parent": "' + records[entry][0] + '", "node_type": "info"}')
              }else{
                new_node = JSON.parse('{"id": "'+ match[1] + '", "parent": "' + records[entry][0] + '", "node_type": "server"}')
              }
              io.emit('add_node', new_node)
            }
          } while (match);
          myRegexp = /include:([^\s]+)/g
          do {
            match = myRegexp.exec(records[entry]);
            if (match) {
              new_node = JSON.parse('{"id": "'+ match[1] + '", "parent": "' + records[entry][0] + '", "node_type": "network"}')
              io.emit('add_node', new_node)
            }
          } while (match);
          myRegexp = /a:([^\s]+)/g
          do {
            match = myRegexp.exec(records[entry]);
            if (match) {
              new_node = JSON.parse('{"id": "'+ match[1] + '", "parent": "' + records[entry][0] + '", "node_type": "subdomain"}')
              io.emit('add_node', new_node)
            }
          } while (match);
        }
      }
    })
  });

  socket.on('nameservers', function(query){
    dns.resolveNs(query, function(err, records){
      for (entry in records){
        new_node = JSON.parse('{"id": "'+ records[entry] + '", "parent": "' + query + '", "node_type": "nameserver"}')
        io.emit('add_node', new_node)
      }
    })
  });

  socket.on('ip_lookup', function(query_object){
    //run a ping sweep if this is a CIDR range
    if(query_object.node_type == "cidr"){
      var block = new netmask(query_object.node_id);
      block.forEach(function(host){
        ping.sys.probe(host, function(isAlive){
            if(isAlive){
              new_node = JSON.parse('{"id": "'+ host + '", "parent": "' + query_object.node_id + '", "node_type": "server"}')
              io.emit('add_node', new_node)
            }
        });

      });
    }else{
      dns.resolve(query_object.node_id.toString(), function(err, addresses){
        for (server in addresses){
          new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + query_object.node_id + '", "node_type": "server"}')
          io.emit('add_node', new_node)
        }
      })
    }
  });

  socket.on('export_graph', function(query_object){
    if(query_object.file_name == ""){
      query_object.file_name = "export"
    }
    if(query_object.export_type == 'list'){
      fs.writeFile("./" + query_object.file_name, query_object.export_list, function(err) {
        if(err) {
          console.log(err);
        }
        io.emit('server_message', "File Exported: ./" + query_object.file_name)
      });
    }else{
      fs.writeFile("./" + query_object.file_name + "_" + dateFormat(new Date(), "yyyy-mm-dd_HH-MM-ss")+".js", JSON.stringify(query_object.graph_object,false, 2), function(err) {
        if(err) {
          console.log(err);
        }
        io.emit('server_message', "File Exported: ./" + query_object.file_name + "_" +dateFormat(new Date(), "yyyy-mm-dd_HH-MM-ss")+".js")
      });
    }
  });

  socket.on('subdomain_lookup', function(query){
    http_resolver.get('http://api.hackertarget.com/hostsearch/?q=' + query,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        lines = data.split('\n')
        for(line in lines){
          subdomain = lines[line].split(',')
          subdomain_name = subdomain[0]
          subdomain_ip = subdomain[1]
          if(subdomain_name.split('.').length == 2){
            new_node = JSON.parse('{"id": "'+ subdomain_name + '", "parent": "' + query + '", "node_type": "network"}')
          }else{
            new_node = JSON.parse('{"id": "'+ subdomain_name + '", "parent": "' + query + '", "node_type": "subdomain"}')
          }
          io.emit('add_node', new_node)
          new_node = JSON.parse('{"id": "'+ subdomain_ip + '", "parent": "' + subdomain_name + '", "node_type": "server"}')
          io.emit('add_node', new_node)
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });

    https_resolver.get('https://otx.alienvault.com/api/v1/indicators/domain/' + query + '/passive_dns',  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data).passive_dns
        for(i=0;i<results.length;i++){
          new_node = JSON.parse('{"id": "'+ results[i].hostname + '", "parent": "' + query + '", "node_type": "subdomain"}')
          io.emit('add_node', new_node)
          if(results[i].address){
            new_node = JSON.parse('{"id": "'+ results[i].address + '", "parent": "' + results[i].hostname + '", "node_type": "server"}')
            io.emit('add_node', new_node)
          }
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('asn_search', function(query_object){
    var api_call = 'http://asnlookup.com/api/lookup?org=' + encodeURIComponent(query_object.node_id)
//    if(query_object.node_type == "server"){
//      api_call = 'http://10.0.50.105:10120/ip_to_asn?q=' + query_object.node_id
//    }else if(query_object.node_type == "info"){
//      api_call = 'http://10.0.50.105:10120/asn_to_org?q=' + query_object.node_id.replace(/ASN:/,'')
//    }else{
//      api_call = 'http://10.0.50.105:10120/org_to_asn?q=' + query_object.node_id
//    }
    http_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data)
        for(result in results){
//          new_node = JSON.parse('{"id": "'+ results[result].org + '", "parent": "' + query_object.node_id + '", "node_type": "organization"}')
//          io.emit('add_node', new_node)
//          new_node = JSON.parse('{"id": "ASN:'+ results[result].asn + '", "parent": "' + results[result].org + '", "node_type": "info"}')
//          io.emit('add_node', new_node)
          new_node = JSON.parse('{"id": "' + results[result] + '", "parent": "' + query_object.node_id + '", "node_type": "cidr"}')
          io.emit('add_node', new_node)
//          new_node = JSON.parse('{"id": "Country:'+ results[result].country + '", "parent": "' + results[result].org + '", "node_type": "info"}')
//          io.emit('add_node', new_node)
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('dox_ns', function(query){
    http_resolver.get('http://10.0.50.105:10120/search?q=' + query,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data)
        for(result in results){
          subdomain_name = results[result].name
          subdomain_ip = results[result].value
          if(subdomain_name.split('.').length == 2){
            new_node = JSON.parse('{"id": "'+ subdomain_name + '", "parent": "' + query + '", "node_type": "network"}')
          }else{
            new_node = JSON.parse('{"id": "'+ subdomain_name + '", "parent": "' + query + '", "node_type": "subdomain"}')
          }
          io.emit('add_node', new_node)
          
          if(results[result].type == 'cname'){
            if(subdomain_name.split('.').length == 2){
              new_node = JSON.parse('{"id": "'+ subdomain_ip + '", "parent": "' + subdomain_name + '", "node_type": "network"}')
            }else{
              new_node = JSON.parse('{"id": "'+ subdomain_ip + '", "parent": "' + subdomain_name + '", "node_type": "subdomain"}')
            }
          }else{
            new_node = JSON.parse('{"id": "'+ subdomain_ip + '", "parent": "' + subdomain_name + '", "node_type": "server"}')
          }
          io.emit('add_node', new_node)
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('reverse_dox_ns', function(query){
    http_resolver.get('http://10.0.50.105:10120/reverse_search?q=' + query,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data)
        for(result in results){
          subdomain_name = results[result].name
          subdomain_ip = results[result].value
          if(subdomain_name.split('.').length == 2){
            new_node = JSON.parse('{"id": "'+ subdomain_name + '", "parent": "' + query + '", "node_type": "network"}')
          }else{
            new_node = JSON.parse('{"id": "'+ subdomain_name + '", "parent": "' + query + '", "node_type": "subdomain"}')
          }
          io.emit('add_node', new_node)
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('crtsh_lookup', function(query){
    https_resolver.get('https://crt.sh/?q=%25.' + query,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        myRegexp = new RegExp(`<TD>([^>\ =]+\.${query})`, 'g')
        do {
          match = myRegexp.exec(data);
          if (match) {
            if(match[1].split('.').length > 2){
              new_node = JSON.parse('{"id": "'+ match[1].toLowerCase() + '", "parent": "' + query + '", "node_type": "subdomain"}')
              io.emit('add_node', new_node)
            }else{
              new_node = JSON.parse('{"id": "'+ match[1].toLowerCase() + '", "parent": "' + query + '", "node_type": "network"}')
              io.emit('add_node', new_node)
            }
          }
        } while (match);
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('bruteforce_subdomains', function(query){
    //console.log(dateFormat("isoDateTime") + " starting bruteforce");
    dns.resolve('notavalidsubdomain.' + query, function(err, wildcardIP){
      if(wildcardIP){
        new_node = JSON.parse('{"id": "*.' + query + '", "parent": "' + query + '", "node_type": "subdomain"}')
        io.emit('add_node', new_node)
        new_node = JSON.parse('{"id": "'+ wildcardIP[0] + '", "parent": "*.' + query + '", "node_type": "server"}')
        io.emit('add_node', new_node)
      }else{
        wildcardIP = ['1.1.1.1']
      }
      var lineReader = require('readline').createInterface({
        //input: fs.createReadStream('./lists/servers.txt')
        input: fs.createReadStream('./lists/alexaTop1mAXFRcommonSubdomains.txt')
      });
      lineReader.on('line', function (subdomain) {
        dns.resolve(subdomain + '.' + query, function(err, addresses){
          if (typeof(addresses) !== 'undefined'){
            if(addresses[0] !== wildcardIP[0]){
              new_node = JSON.parse('{"id": "'+ subdomain + '.' + query + '", "parent": "' + query + '", "node_type": "subdomain"}')
              io.emit('add_node', new_node)
              for (server in addresses){
                new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + subdomain + '.' + query + '", "node_type": "server"}')
                io.emit('add_node', new_node)
              }
            }
          }
        })
      })
    })
    lineReader.on('close', function () {
      //console.log(dateFormat("isoDateTime") + " finished bruteforce");
    });
  });

  socket.on('port_scan', function(query_object){
    //console.log(dateFormat("isoDateTime") + " starting port scan");
    if(query_object.node_type == 'cidr'){
       var block = new netmask(query_object.node_id);
       target_range = block.first + "-" + block.last
    }else{
      target_range = query_object.node_id
    }
    let options = {
        target : target_range,
        // target  :'192.168.1.1-5',
        // target  :'192.168.1.1-192.168.1.5',
        //port    :'21, 22, 23, 25, 80, 443, 4443, 4444, 3389, 139, 137, 8443, 8080',
        port    : query_object.port_list,
        //status  : 'TROU', // Timeout, Refused, Open, Unreachable
        status  : 'O', // Timeout, Refused, Open, Unreachable
        timeout : 3000,
        banner  : false,//maybe we can collect this later. Might slow down the scans though
        //geo	    : true
    };

    let scanner = new evilscan(options);
    scanner.on('result',function (data) {
    	// fired when item is matching options
    	//console.log(data);
        //make sure to create ip nodes if we are scanning a range
        if(query_object.node_type == 'cidr'){
          new_node = JSON.parse('{"id": "'+ data.ip + '", "parent": "' + query_object.node_id + '", "node_type": "server"}')
          io.emit('add_node', new_node)
          new_node = JSON.parse('{"id": "'+ data.ip + ':' + data.port + '", "parent": "' + data.ip + '", "node_type": "port"}')
          io.emit('add_node', new_node)
        }else{
          new_node = JSON.parse('{"id": "'+ data.ip + ':' + data.port + '", "parent": "' + query_object.node_id + '", "node_type": "port"}')
          io.emit('add_node', new_node)
        }
    });
    scanner.on('error',function (err) {
    	//throw new Error(data.toString());
    	console.log(data.toString());
    });
    scanner.on('done',function () {
      //console.log(dateFormat("isoDateTime") + " finished port scan");
    });
    scanner.run();
  });

  socket.on('location_search', function(query_object){
    api_call = {
      hostname: 'ipapi.co',
      path: '/' + query_object + '/json/',
      headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36' }
    };
    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        location_results = JSON.parse(data)
        try{
          new_node = JSON.parse('{"id": "'+ location_results.latitude + ':' + location_results.longitude + '", "parent": "' + query_object + '", "node_type": "location"}')
          io.emit('add_node', new_node)
        }catch (err){
        }
        try{
          new_node = JSON.parse('{"id": "State: '+ location_results.region + '", "parent": "' + query_object + '", "node_type": "info"}')
          io.emit('add_node', new_node)
        }catch (err){
        }
        try{
          new_node = JSON.parse('{"id": "City: '+ location_results.city + '", "parent": "' + query_object + '", "node_type": "info"}')
          io.emit('add_node', new_node)
        }catch (err){
        }
        try{
          new_node = JSON.parse('{"id": "'+ location_results.org + '", "parent": "' + query_object + '", "node_type": "organization"}')
          io.emit('add_node', new_node)
        }catch (err){
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });

  });

  socket.on('convert_to_cidr', function(query_object){
    try{
      query_object = query_object.replace(/[\s\n\r]+/g,'')
      range = query_object.split('-')
      base_ip = range[0]
      limit_ip = range[1]
      for(mask = 32; mask > 0; mask -= 1){
        var block = new netmask(base_ip + "/" + mask.toString());
        if((block.base == base_ip)&(block.broadcast == limit_ip)){
          new_node = JSON.parse('{"id": "'+ base_ip + "/" + mask.toString() + '", "parent": "' + query_object + '", "node_type": "cidr"}')
          io.emit('add_node', new_node)
          //console.log(block)
        }
      }
    }catch (err){
      io.emit('server_message', "Error Converting to CIDR: " + err)
    }
  });

  socket.on('zone_transfer', function(query){
    dns.resolveNs(query, function(err, records){
      for (entry in records){
        new_node = JSON.parse('{"id": "'+ records[entry] + '", "parent": "' + query + '", "node_type": "nameserver"}')
        io.emit('add_node', new_node)
        axfr.resolveAxfrTimeout(1000);
        axfr.resolveAxfr(records[entry], query, function(err, addr) {
          if (err) {
            //console.error('Error ocurred: ' + addr + ' (' + err + ')');
            return;
          }
          results = addr.answers
          for(i=0;i<results.length;i++){
            if(results[i].name.slice(-1) == '.'){
              results[i].name = results[i].name.slice(0, -1)
            }
            new_node = JSON.parse('{"id": "'+ results[i].name + '", "parent": "' + query + '", "node_type": "subdomain"}')
            io.emit('add_node', new_node)
            if(results[i].dns){
              new_node = JSON.parse('{"id": "'+ results[i].dns.slice(0, -1) + '", "parent": "' + results[i].name + '", "node_type": "nameserver"}')
              io.emit('add_node', new_node)
            }
            if(results[i].mail){
              new_node = JSON.parse('{"id": "'+ results[i].mail.slice(0, -1) + '", "parent": "' + results[i].name + '", "node_type": "mail"}')
              io.emit('add_node', new_node)
            }
            if(results[i].a){
              new_node = JSON.parse('{"id": "'+ results[i].a + '", "parent": "' + results[i].name + '", "node_type": "server"}')
              io.emit('add_node', new_node)
            }
          }
        })
      }
    })
  });

  socket.on('hunter_api_check', function(query_object){

    api_call = 'https://api.hunter.io/v2/account?api_key=' + query_object

    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        try{
          results = JSON.parse(data)
          io.emit('server_message', "Used: " + results.data.calls.used + "\nAvailable: " + (results.data.calls.available - results.data.calls.used) + "\nResets: " + results.data.reset_date)
        }catch (err){
          io.emit('server_message', "There is a problem with your API key")
        }
      });
    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });


  socket.on('email_search', function(query_object){

    api_call = 'https://sks-keyservers.net/pks/lookup?search=' + query_object.node_id 
    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        myRegexp = />([^<]+@[^<]+)/g
        do {
          match = myRegexp.exec(data);
          if (match) {
            name = match[1].slice(0, match[1].indexOf('&lt;'))
            email = match[1].slice(match[1].indexOf('&lt;')+4, match[1].indexOf('&gt;'))
            new_node = JSON.parse('{"id": "'+ email + '", "parent": "' + query_object.node_id + '", "node_type": "email"}')
            io.emit('add_node', new_node)
            new_node = JSON.parse('{"id": "'+ name + '", "parent": "' + email + '", "node_type": "person"}')
            io.emit('add_node', new_node)
          }
        } while (match);
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });

    api_call = 'https://api.hunter.io/v2/domain-search?limit=1000&domain=' + query_object.node_id + '&api_key=' + query_object.hunter_api_key

    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data)
        if(results.data.pattern){
          new_node = JSON.parse('{"id": "Mail Pattern:'+ results.data.pattern + '", "parent": "' + query_object.node_id + '", "node_type": "info"}')
          io.emit('add_node', new_node)
        }
        if(results.data.organization){
          new_node = JSON.parse('{"id": "'+ results.data.organization + '", "parent": "' + query_object.node_id + '", "node_type": "organization"}')
          io.emit('add_node', new_node)
        }
        for(i=0; i < results.data.emails.length; i++){
          email = results.data.emails[i]
          new_node = JSON.parse('{"id": "'+ email.value + '", "parent": "' + query_object.node_id + '", "node_type": "email"}')
          io.emit('add_node', new_node)
          if(email.first_name && email.last_name){
            new_node = JSON.parse('{"id": "'+ email.first_name + ' ' + email.last_name + '", "parent": "' + email.value + '", "node_type": "person"}')
            io.emit('add_node', new_node)
          }else if(email.first_name){
            new_node = JSON.parse('{"id": "'+ email.first_name + '", "parent": "' + email.value + '", "node_type": "person"}')
            io.emit('add_node', new_node)
          }else if(email.last_name){
            new_node = JSON.parse('{"id": "'+ email.last_name + '", "parent": "' + email.value + '", "node_type": "person"}')
            io.emit('add_node', new_node)
          }
          if(email.position){
            new_node = JSON.parse('{"id": "'+ email.position + '", "parent": "' + email.value + '", "node_type": "position"}')
            io.emit('add_node', new_node)
          }
          if(email.twitter){
            new_node = JSON.parse('{"id": "www.twitter.com/'+ email.twitter + '", "parent": "' + email.value + '", "node_type": "info"}')
            io.emit('add_node', new_node)
          }
          if(email.linkedin){
            new_node = JSON.parse('{"id": "www.linkedin.com/in/'+ email.linkedin + '", "parent": "' + email.value + '", "node_type": "info"}')
            io.emit('add_node', new_node)
          }
          if(email.phone_number){
            new_node = JSON.parse('{"id": "'+ email.phone_number + '", "parent": "' + email.value + '", "node_type": "phone"}')
            io.emit('add_node', new_node)
          }
          for(j=0; j < email.sources.length; j++){
            source = email.sources[j]
            new_node = JSON.parse('{"id": "Email Source:'+ source.uri + '", "parent": "' + email.value + '", "node_type": "info"}')
            io.emit('add_node', new_node)
          }
        }
      });
    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('query_shodan', function(query_object){
    if(query_object.node_type == "organization"){
      api_call = 'https://api.shodan.io/shodan/host/search?query=org:"' + encodeURIComponent(query_object.node_id) + '"&key=' + query_object.api_key
    }else if((query_object.node_type == "cidr") || (query_object.node_type == "server")) {
      api_call = 'https://api.shodan.io/shodan/host/search?query=net:' + encodeURIComponent(query_object.node_id) + '&key=' + query_object.api_key
    }else{
      api_call = 'https://api.shodan.io/shodan/host/search?query=hostname:' + encodeURIComponent(query_object.node_id) + '&key=' + query_object.api_key
    }
    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        shodan_results = JSON.parse(data)
        for(i=0; i < shodan_results.matches.length; i++) {
          match = shodan_results.matches[i]
          try {
            server = match.ip_str
            new_node = JSON.parse('{"id": "'+ server + '", "parent": "' + query_object.node_id + '", "node_type": "server"}')
            io.emit('add_node', new_node)
            host_names = match.hostnames
            for (j=0; j < host_names.length; j++) {
              subdomain = host_names[j]
              new_node = JSON.parse('{"id": "'+ subdomain + '", "parent": "' + server + '", "node_type": "subdomain"}')
              io.emit('add_node', new_node)
            }
            network_names = match.domains
            for (j=0; j < network_names.length; j++) {
              network = host_names[j]
              new_node = JSON.parse('{"id": "'+ network + '", "parent": "' + server + '", "node_type": "network"}')
              io.emit('add_node', new_node)
            }
            if(match.port){
              new_node = JSON.parse('{"id": "'+ server + ":" + match.port + '", "parent": "' + server + '", "node_type": "port"}')
              io.emit('add_node', new_node)
            }
            if(match.location.longitude){
              new_node = JSON.parse('{"id": "'+ match.location.latitude + ":" + match.location.longitude + '", "parent": "' + server + '", "node_type": "location"}')
              io.emit('add_node', new_node)
              if(match.location.city){
                new_node = JSON.parse('{"id": "City: '+ match.location.city + '", "parent": "' + match.location.latitude + ":" + match.location.longitude + '", "node_type": "info"}')
                io.emit('add_node', new_node)
              }
              if(match.location.region_code){
                new_node = JSON.parse('{"id": "State: '+ match.location.region_code + '", "parent": "' + match.location.latitude + ":" + match.location.longitude + '", "node_type": "info"}')
                io.emit('add_node', new_node)
              }
            }
            if(match.org){
              new_node = JSON.parse('{"id": "'+ match.org + '", "parent": "' + server + '", "node_type": "organization"}')
              io.emit('add_node', new_node)
            }
          } catch (err) {
            console.log(err);
          }
        }
      });
    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('linkedin_search', function(query_object){
    linkedinMiner(query_object.node_id, io, query_object.linkedin_cookie, query_object.org_id, query_object.start_page, query_object.end_page)
  });

  socket.on('open_file', function(query_object){
    glob(query_object.file_path, function (er, files) {
      for (var i=0; i<files.length; i++) {
        io.emit('server_message', "Importing File: " + files[i])
        fs.readFile(files[i], function(err,scope_file){
          file_lines = scope_file.toString().split('\n')
          for(i=0; i<file_lines.length; i++){
            if(file_lines[i].indexOf('/') !== -1){
              new_node = JSON.parse('{"id": "'+ file_lines[i] + '", "parent": "' + query_object.parent_node + '", "node_type": "cidr"}')
              io.emit('add_node', new_node)
            } else if(file_lines[i].split('.').length == 4){
              new_node = JSON.parse('{"id": "'+ file_lines[i] + '", "parent": "' + query_object.parent_node + '", "node_type": "server"}')
              io.emit('add_node', new_node)
            } else if(file_lines[i].split('.').length == 3){
              new_node = JSON.parse('{"id": "'+ file_lines[i] + '", "parent": "' + query_object.parent_node + '", "node_type": "subdomain"}')
              io.emit('add_node', new_node)
            } else {
              new_node = JSON.parse('{"id": "'+ file_lines[i] + '", "parent": "' + query_object.parent_node + '", "node_type": "network"}')
              io.emit('add_node', new_node)
            }
          }
        });
      }
    })
  });

  socket.on('open_graph', function(graph_path){
    //check if we need to import any graphs
    glob(graph_path, function (er, files) {
      for (var i=0; i<files.length; i++) {
        io.emit('server_message', "Importing Graph: " + files[i])
        fs.readFile(files[i], function(err,graph_file){
          graph_import = JSON.parse(graph_file);
          for(i=0; i<graph_import.nodes.length; i++){
            io.emit('import_node', graph_import.nodes[i])
          }
          for(i=0; i<graph_import.links.length; i++){
            io.emit('import_link', graph_import.links[i])
          }
        });
      }
    })
  });

});

http.listen(3000, function(){
  //console.log('listening on *:3000');
  console.log('listening on *:3000');
});

//catch any server exceptions instead of exiting
http.on('error', function (e) {
  console.log(dateFormat("isoDateTime") + " " + e);
});

//catch any node exceptions instead of exiting
process.on('uncaughtException', function (err) {
  console.log(dateFormat("isoDateTime") + " " + 'Caught exception: ', err);
});

function wait (timeout) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve()
    }, (timeout + Math.random()*1000))
  })
}

//sorry this function is so funky! had to do some sync gynastics to keep enumeration to a human level so we don't get busted ;D
async function linkedinMiner(parent_node, io, linkedin_cookie, org_id, start_page, end_page) {
  async function launchChrome() {
    return await chromeLauncher.launch({
      chromeFlags: [
        '--headless',
        '--disable-gpu'
      ]
    });
  }
  const chrome = await launchChrome();
  const protocol = await CDP({
    port: chrome.port
  });

  const {
    DOM,
    Page,
    Emulation,
    Runtime
  } = protocol;

  await Promise.all([Page.enable(), Runtime.enable(), DOM.enable()]);
  await protocol.Network.setCookie({
    name: "li_at",
    value: linkedin_cookie,
    domain: "www.linkedin.com"
  })

  async function getPage(page_number){
    return new Promise(async function(resolve, reject){
      Page.navigate({
        url: 'https://www.linkedin.com/search/results/people/?facetCurrentCompany=%5B%22' + org_id + '%22%5D&page=' + page_number
      });
  
      Page.loadEventFired(async() => {
        await wait(2000)
        script1 = "window.scrollTo(0,(document.body.scrollHeight/2));"
        result = await Runtime.evaluate({
          expression: script1
        });
        await wait(2000)
        script1 = "window.scrollTo(0,document.body.scrollHeight);"
        result = await Runtime.evaluate({
          expression: script1
        });
        await wait(2000)
//         script1 = 'names = document.getElementsByClassName("name actor-name");output = "";for (i = 0; i < names.length; i++){ if (names[i].text != "LinkedIn Member"){output = output + "\\n" + (names[i].innerHTML)}};output;'
         script1 = 'names = document.getElementsByClassName("name actor-name");output = "";for (i = 0; i < names.length; i++){ if (names[i].text != "LinkedIn Member"){output = output + "\\n" + (names[i].innerHTML + ":" + names[i].parentNode.parentNode.parentNode.parentNode.parentNode.getElementsByTagName("p")[0].textContent.trim())}};output;'

        result = await Runtime.evaluate({
          expression: script1
        });

        resolve(result.result.value);
      });
    });
  }

  for (i=start_page;i<=end_page;i++) {
    results = await getPage(i).catch( e => { } )
    employees = results.split('\n')
    //console.log(employees);
    for(j=0; j<employees.length;j++){
      employee = employees[j]
      if(employee !== ''){
        try{
          new_node = JSON.parse('{"id": "' + org_id + ' page ' + i + '", "parent": "' + parent_node + '", "node_type": "linkedin"}')
          io.emit('add_node', new_node)
          name_position = employee.split(':')
          new_node = JSON.parse('{"id": "' + name_position[0] + '", "parent": "' + org_id + ' page ' + i + '", "node_type": "person"}')
          io.emit('add_node', new_node)
          new_node = JSON.parse('{"id": "' + name_position[1] + '", "parent": "' + name_position[0] + '", "node_type": "position"}')
          io.emit('add_node', new_node)
        }catch (err){
          console.log(name_position)
        }
      }
    }
  }

  protocol.close();
  chrome.kill();

}
