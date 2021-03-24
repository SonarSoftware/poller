<?php

use SonarSoftware\Poller\Services\TemporaryVariables;

require("/opt/poller/vendor/autoload.php");
 
Resque::setBackend('localhost:6379');
Resque::dequeue('polling');

TemporaryVariables::set("SNMP Polling Running",null);
TemporaryVariables::set("ICMP Polling Running",null); 
