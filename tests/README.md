# cs6250-spring21-p4-tests

*This project was forked from a former student's project for the summer 2020 semester and modified to work with the new project in the spring 2021 semester: jscott318/cs6250-summer20-p4-tests*

Clone the repo into your project folder as a folder named tests
```
git clone https://github.gatech.edu/jtucker87/cs6250-spring21-p4-tests.git tests
```

cd into tests
```
cd tests
```

Run the tests script
```
./test.sh
```  
**It could take several minutes to complete the entire suite**  
The output will list the Passed and Failed test cases.  
It will output something like this:

```
mininet@mininet:~/SDNFirewall/tests$ ./test.sh
Running the tests against configure.pol to test rules given in project
........
----------------------------------------------------------------------

Testing Rule 1 - DNS
<tests Passed or Failed listed here>
Passed: {"client": "wo1", "server": "hq1", "port": 53, "proto": "udp", "retries": 1, "assert_value": True}
.
.
Testing Rule 2 - OpenVPN
<tests Passed or Failed listed here>
Passed: {'client': 'wo1', 'server': 'hq3', 'port': 1194, 'proto': 'tcp', 'retries': 1, 'assert_value': False}
.
.

OK
```

## Testing individual tests
If you want to run an indvidual test without running the whole suite, run the appropriate firewall command in another terminal and then you can run a single test or a whole file of tests.

To run the tests against your configure.pol for rule 1 use this command.
```
sudo python -m unittest test_config_policy.YourTestCase.test_rule_1
```  

## Debug Mode and Adding more tests
All of the main project tests are located in `test_config_policy.py` with each of the 7 Rules from the project in a separate function test.  
**UPDATE: Extra tests have been added to test the firewall implementation with a new topo and a new set of firewall rules. These can be found in the following files:  
`firewall-policies-other.pol`, `test_firewall_topo.py` (Class `OtherFWTopo`), and `test_other.py`.  
*These will be run as part of the main script: `test.sh`***  

The tests are made up of multiple  `rule` dictionaries that are read into the test framework.   
To turn on debug mode, add a `"debug": True` element to the dictionary.  
  
It could be useful to comment out some Tests as needed.

*Note:`test_policy_good.py` is a remnant of the older repo and is not currently being used.  
