Scope Creep
=====
A mass target enumeration tool

Installation 
=====
This project is written in Node.js for its flexibility and non-blocking I/O.
You will need to install Node and NPM (Node Package Manager) to run the project: [Node.js Download](https://nodejs.org/en/download/)

Clone the repo and install the dependencies:
```
git clone https://github.com/fkasler/scope_creep.git
cd scope_creep
npm install
```

Getting Started
=====

- start the server and navigate to [http://localhost:3000](http://localhost:3000) in Chrome to get started:

```
node index.js
```

Usage/Modules
=====

- Scope Creep was built on Chrome. I hear the key bindings don't work on Firefox. You may experience issues with browsers other than Chrome. You've been warned.
- By default, "Safety" Mode is turned on to prevent the accidental running of mass queries against CIDR ranges and port scanning or ping sweeping anything. You can turn it off if you know what you're doing.
- You can trigger modules by clicking on them in the help menu. However, it's faster and more fun to learn the key bindings.
- You can select multiple nodes by either clicking on their row in the stats list or by using the node search.
- Node search/find(f) supports JavaScript regular expressions (e.g. 'domain.com' will select the domain and its subdomains but '^domain.com' will only select the domain and no subs). [regex reference](https://eloquentjavascript.net/09_regexp.html)
- Add values for [shodan](https://www.shodan.io/) api key, [whoxy](https://www.whoxy.com/reverse-whois/) api key, [li_at](https://www.linkedin.com/) cookie, and [hunter.io](https://hunter.io/users/sign_up) api key to use those features. The value is saved in a cookie when you click out of the input so that they persist between page reloads.
- The li_at cookie is LinkedIn's session cookie and required to mine LinkedIn with Scope Creep. I recommend [editthiscookie](http://www.editthiscookie.com/) extension for Chrome to get your current session cookie.

### Add Node(a):
Press 'a' to select and clear the "Add Node(a)" input box. Hit enter to add the node to the graph.

### Help(h):
Toggles the help window in and out of the screen.

### Hide Stats(H):
Toggles the Stats list in and out of the screen.

### Connect Nodes(c):
Select a node, hit 'c', and select another node to connect them. Press 'c' again to cancel if you accidentally hit it.

### Copy Nodes to Clipboard(y):
Yank the contents of the selected nodes to your clipboard. Useful for fast export of data like pulling an addresses.txt for phishing.

### Export Nodes(e):
Export the contents of the selected nodes to a file name of your choosing. If you include the word 'finding' in the file name, the selected nodes will be exported in the format that Engage expects for finding imports. This is great for turning open port nodes into a finding like "Internet accessible authentication prompts".

### Export Graph(E):
Export the entire graph as a JSON object to a file. Useful for saving progress or sharing graphs with others.

### Select Nodes based on # of connections (0-9):
Select nodes based on how many nodes are connected to them. Good for some mass operations.

### Open Scope File(o):
Open a scope file with domains, subdomains, IPs, and CIDR ranges in it. This module needs you to select a parent node for the entries to attach to so they don't go flying in all directions. Supports wildcard imports (e.g. scope_file\* would import scope_file1.txt, scope_file2.txt, and scope_file_more_entries.txt)

### Open Graph(O):
Open a saved graph. This also supports wildcards. Wildcards are a great way to combine graphs into a single scope graph.

### Delete Nodes(d):
Deletes all selected nodes.

### Delete Unselected Nodes(D):
Deletes everything except the currently selected nodes. Great to use in combo with (f).

### Undo Deleted Nodes(u):
You can bring back connections to the selected nodes by using the undo feature. Useful for pairing down and building back graphs based on search criteria.

### Change Node Type(U):
Lets you update the node type for a single selected node.

### Whois Lookup(w):
Performs a Whois lookup on the selected IP node.

### Whoxy Reverse Whois Lookup(W):
Searches the Whoxy API for related domains based on Organization name, technical contact email, or keyword search. To search domain nodes like "example.com", use option (c) when prompted.

### MX Query(m):
Performs a DNS MX lookup on the selected nodes. Useful for quickly getting a list of mail servers.

### Reverse DNS Lookup(r):
Performs a DNS reverse lookup on the selected nodes. If a CIDR range is selected, it will do a reverse lookup for all possible IPs in the range. Great for quickly finding hosts on a network.

### Mass Reverse DNS Lookup(R):
Performs a DNS reverse lookup on ALL IP nodes in the graph.

### TXT Records(t):
Performs a DNS TXT lookup on the selected nodes. This module also tries to parse out CIDR ranges, hosts, and domains from SPF records.

### Mass TXT Records(T):
Same as (t), but against all domain nodes. This is great for enumerating runaway SPF records quickly.

### Name Servers(n):
Performs a DNS NS lookup on the selected nodes.

### Generate Emails(g):
Generates emails from all person nodes in the graph. If you leave the domain blank, it will not include the @ symbol so this is also good for generating usernames.

### Generate Phishmonger Target CSV(G):
Exports a CSV to the clipboard that contains a social engineering targets list. Useful in combination with the LinkedIn scraper and Hunter.io results.

### View Website in New Tab(v):
Opens a new Chrome tab for the selected nodes. Great for viewing web portals.

### Mass View Website in New Tab(V):
Opens a new Chrome tab for every subdomain node in the graph. Great for a quick look at subs to see what they're hosting.

### ASN search(A):
Searches for IP ranges that belong to an organization by querying the [http://asnlookup.com/](http://asnlookup.com/) API. The public repo only supports forward lookups based on organization name. I will link to resources on setting up a better API sometime in the future.

### DoxNS Lookup(x):
Proprietary DB for now. I will link to more details sometime in the future.

### Reverse DoxNS Lookup(X):
Proprietary DB for now. I will link to more details sometime in the future.

### IP DNS Query/Ping Sweep CIDR(i):
Performs a DNS lookup for the selected nodes. If a CIDR range is selected, this module performs an ICMP ping sweep on the range equivalent to 'nmap -sn -PE 192.168.0.0/24'. Ping sweeps are not allowed in safety mode.

### Mass IP DNS Query/Ping Sweep CIDR(I):
Performs a DNS lookup for ALL subdomain and CIDR nodes. CIDR is not scanned if safty mode is turned on. If a CIDR range is selected, this module performs an ICMP ping sweep on the range equivalent to 'nmap -sn -PE 192.168.0.0/24'

### Subdomain Lookup (limit 100 queries/day)(s):
Performs a subdomain search using alienvault's free API and hackertarget.com's free API. Limited to 100 queries per day. That's a lot of free data.

### CRT.SH Subdomain Lookup (unknown limit)(S):
Performs a subdomain search using crt.sh. This can find some cool stuff when it works. Sometimes you can even find internal domain names if the org uses the same cert for internal and external use.

### Query Shodan (rate limit 1 per second)(q):
Performs a Shodan query on the selected node. One node at a time limit because Shodan only allows a query per second or so and Node.js would try to do them all at once.

### LinkedIn Search (deactivation risk, DO NOT THREAD!)(l):
Mines LinkedIn for employee names and positions using a headless Chrome browser that mimics a human scrolling through pages. You need to make sure you have a current li_at cookie set first. You also need to select a node for the results to attach to. Go search for your target org in LinkedIn and get the OrgID and the number of results pages you want to mine. The OrgId for "https://www.linkedin.com/search/results/people/?facetCurrentCompany=11452158" would be 11452158. Sometimes you'll see multiple OrgIds. In those cases, just mine them one after the other. DO NOT TRY TO SPEED UP OR THREAD THIS MODULE!!!!!!!!! YOU CAN GET BUSTED AND ACCOUNT SUSPENDED!!!! It is slow for a reason.

### Email Search (limit 100 queries/month)(M):
Performs a Hunter.io email search and a SKS-KeyServer email search. Go get a free Hunter.io account and grab the api key. The free API allows 100 results per month but 10 emails is equal to one result. The max emails per query is 100 so that will burn 10 "queries" if you get 100 results. In effect, you are limited to an absolute maximum of 1,000 emails per month with the free account. I recommend exporting and looking through the email sources that it returns. They can point to directories and places to get other emails. They can also give you an idea of other organizations that your target works with. Great for blackbox testing.

### Location Search (general rate limit)(L):
Tries to find the Lat/Long location associated with an IP. You can view location nodes in Google maps by using the "View Website in New Tab(v)" module.

### DNS Zone Transfer(Z):
Performs a Zone Transfer against the selected domain/network nodes. This will run a axfr query against ALL name servers for the domain so it can be noisy if successful.

### Bruteforce Subdomains (interacts with client servers)(b):
Performs DNS subdomain bruteforcing using the alexa list from fuzzdb. This can take a while but generally goes fast on private networks. Great for quickly finding hosts with DNS on internal assessments/SE.

### Port Scan/Port Scan ALL IPs(p):
Performs a TCP port scan on the selected nodes. Supports individual CIDR ranges. You specify the ports/ranges in the ports input field. You can mix ports and ranges if you'd like (e.g. 21-15,80,443,8080,4444-555). Not allowed in safety mode.

### Mass Port Scan/Port Scan ALL IPs(P):
Performs a TCP port scan on ALL IP nodes. You specify the ports/ranges in the ports input field. You can mix ports and ranges if you'd like (e.g. 21-15,80,443,8080,4444-555). Not allowed in safety mode.
