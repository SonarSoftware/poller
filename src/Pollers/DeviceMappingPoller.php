<?php

namespace SonarSoftware\Poller\Pollers;

use Dotenv\Dotenv;
use Exception;
use Monolog\Logger;
use SNMP;
use SonarSoftware\Poller\DeviceMappers\Cambium\CambiumCanopyPMPAccessPointMapper;
use SonarSoftware\Poller\DeviceMappers\Cambium\CambiumEpmpAccessPointMapper;
use SonarSoftware\Poller\DeviceMappers\Cambium\CambiumPTP250Backhaul;
use SonarSoftware\Poller\DeviceMappers\Cambium\CambiumPTP500Backhaul;
use SonarSoftware\Poller\DeviceMappers\Cambium\CambiumPTP600Backhaul;
use SonarSoftware\Poller\DeviceMappers\Cambium\CambiumPTP650Backhaul;
use SonarSoftware\Poller\DeviceMappers\Cambium\CambiumPTP670Backhaul;
use SonarSoftware\Poller\DeviceMappers\Cambium\CambiumPTP700Backhaul;
use SonarSoftware\Poller\DeviceMappers\Cambium\CambiumPTP800Backhaul;
use SonarSoftware\Poller\DeviceMappers\Etherwan\EtherwanSwitch;
use SonarSoftware\Poller\DeviceMappers\GenericDeviceMapper;
use SonarSoftware\Poller\DeviceMappers\MikroTik\MikroTik;
use SonarSoftware\Poller\DeviceMappers\Mimosa\MimosaAxAccessPoint;
use SonarSoftware\Poller\DeviceMappers\Mimosa\MimosaBxBackhaul;
use SonarSoftware\Poller\DeviceMappers\Ubiquiti\UbiquitiAirFiber;
use SonarSoftware\Poller\DeviceMappers\Ubiquiti\UbiquitiAirMaxAccessPointMapper;
use SonarSoftware\Poller\DeviceMappers\Ubiquiti\UbiquitiIdentifier;
use SonarSoftware\Poller\Models\Device;
use SonarSoftware\Poller\Services\SonarLogger;

class DeviceMappingPoller
{
    private $snmpForks;
    private $timeout;
    private $log;
    private $retries;
    private $templates;
	private $totalTimeout;

    /**
     * DeviceMappingPoller constructor.
     */
    public function __construct()
    {
        $dotenv = new Dotenv(dirname(__FILE__) . "/../../");
        $dotenv->load();
        $this->snmpForks = (int)getenv("SNMP_FORKS") > 0 ? (int)getenv("SNMP_FORKS") : 25;
        $this->timeout = (int)getenv("SNMP_TIMEOUT") > 0 ? (int)getenv("SNMP_TIMEOUT")*1000000 : 500000;
        $this->retries = (int)getenv("SNMP_RETRIES");
		$this->totalTimeout = (int)getenv("DEVICE_MAPPING_TIMEOUT") > 0 ? (int)getenv("DEVICE_MAPPING_TIMEOUT") * 60 : 300;
        $this->log = new SonarLogger();
    }

    /**
     * Poll a list of devices to determine their connections
     * @param array $work
     * @return array
     */
    public function poll(array $work):array
    {
        if (count($work['hosts']) === 0)
        {
            return [];
        }

        $this->templates = $work['templates'];

        $chunks = array_chunk($work['hosts'],ceil(count($work['hosts'])/$this->snmpForks));

        $results = [];
        $fileUniquePrefix = uniqid(true);

        $pids = [];

        for ($i = 0; $i < count($chunks); $i++)
        {
            $pid = pcntl_fork();
            if (!$pid)
            {
                //Don't parse empty workloads
                if (count($chunks[$i]) === 0)
                {
                    exit();
                }

                $myChunksWithDeviceType = $this->determineDeviceTypes($chunks[$i]);

                $childFile = fopen("/tmp/$fileUniquePrefix" . "_". $i,"w");
                $devices = [];

                foreach ($myChunksWithDeviceType as $hostWithDeviceType)
                {
					$output = false;
                    try {
                        $time_start = microtime(true);
                        $device = new Device();
                        $device->setId($hostWithDeviceType['id']);
                        $device->setSnmpObject($this->buildSnmpObjectForHost($hostWithDeviceType));
						if (getenv('DEBUG') == "true")
						{
							//this allows a savvy user to be able to determine which threads are failing and can whittle down the hosts causing the problems
							$output = fopen("/tmp/".$fileUniquePrefix . "_MAPPER_HOST_" . $hostWithDeviceType['ip'] ,"w");
							fclose($output);
						}
                        //Additional 'case' statements can be added here to break out querying to a separate device mapper
                        $mapper = $this->getDeviceMapper($hostWithDeviceType, $device);
                        $device = $mapper->mapDevice();

                        //figure out if we're running overtime to poll devices
                        $time_end = microtime(true); 
                        $device->setTimer($time_end-$time_start);
                        if (getenv('DEBUG') == "true")
                        {
                            if($device->getTimer() > 25){
                                $this->log->log("{$hostWithDeviceType['ip']} took longer than 25 seconds to poll",Logger::ERROR);
                            }
                        }
                        array_push($devices, $device->toArray());
                    }
                    catch (Exception $e)
                    {
                        if (getenv('DEBUG') == "true")
                        {
                            $this->log->log("Failed to get mappings from {$hostWithDeviceType['ip']}, got {$e->getMessage()}",Logger::ERROR);
                        }
                    }
					if (getenv('DEBUG') == "true")
					{
						unlink("/tmp/".$fileUniquePrefix . "_MAPPER_HOST_" . $hostWithDeviceType['ip']);
					}
                }

                fwrite($childFile,json_encode($devices));
                fclose($childFile);
                unset($devices);

                exit();
            }
            else
            {
                $pids[$pid] = $pid;
            }
        }

		$timeout_start = microtime(true); 
        while (count($pids) > 0)
        {
            foreach ($pids as $pid)
            {
                $res = pcntl_waitpid($pid, $status, WNOHANG);
                if ($res == -1 || $res > 0)
                {
                    unset($pids[$pid]);
                }
            }
			///Get this validated and operational to kill rogue processes so they doesn't lock up the monitoring 
			$timeout_end = microtime(true);
			if($timeout_end-$timeout_start > $this->totalTimeout){
                foreach ($pids as $pid)
                {
                	posix_kill($pid,SIGKILL);
                    if (getenv('DEBUG') == "true")
                    {
                        $this->log->log("Destrying PID" . $pid,Logger::INFO);
                    }
                	$res = pcntl_waitpid($pid, $status, WNOHANG);
					if ($res == -1 || $res > 0)
                	{
                		unset($pids[$pid]);
                	}
                }
            }
            if (getenv('DEBUG') == "true")
            {
			    $this->log->log("Total Pids remaining: ". count($pids),Logger::INFO);
            }
            sleep(1);
        }

        $files = glob("/tmp/$fileUniquePrefix*");
        foreach ($files as $file)
        {
            $output = json_decode(file_get_contents($file),true);
            if (is_array($output))
            {
                $results = array_merge($results,$output);

            }
            unlink($file);
        }

        return $results;
    }

    /**
     * Determine the mapper to use based on the system OID query
     * @param array $hostWithDeviceType
     * @param Device $device
     * @return BaseDeviceMapper (or derivative thereof)
     */
    private function getDeviceMapper(array $hostWithDeviceType, Device $device)
    {
        $oidToMapper = [
            "1.3.6.1.4.1.161" => "CANOPY",
            "1.3.6.1.4.1.2736.1.1" => "ETHERWAN",
            "1.3.6.1.4.1.10002.1" => "UBNT",
            "1.3.6.1.4.1.14988.1" => "MIKROTIK",
            "1.3.6.1.4.1.17713.5" => "CAMBIUMPTP500",
            "1.3.6.1.4.1.17713.6" => "CAMBIUMPTP600",
            "1.3.6.1.4.1.17713.7" => "CAMBIUMPTP650",
            "1.3.6.1.4.1.17713.8" => "CAMBIUMPTP800",
            "1.3.6.1.4.1.17713.9" => "CAMBIUMPTP700",
            "1.3.6.1.4.1.17713.11" => "CAMBIUMPTP670",
            "1.3.6.1.4.1.17713.21" => "CAMBIUMEPMP",
            "1.3.6.1.4.1.17713.250" => "CAMBIUMPTP250",
            "1.3.6.1.4.1.41112.1.3" => "UBNT",
            "1.3.6.1.4.1.41112.1.4" => "UBNT",
            "1.3.6.1.4.1.43356.1.1.1" => "MIMOSABX",
            "1.3.6.1.4.1.43356.1.1.2" => "MIMOSABX",
            "1.3.6.1.4.1.43356.1.1.3" => "MIMOSAAX",
        ];

        $longestOid = 0;
        $m = "GENERIC";

        foreach ($oidToMapper as $enumeration => $mapperName) {
            if (strpos($hostWithDeviceType['type_query_result'], $enumeration) !== false) {
                // initial state, found a match
                if ($longestOid === 0) {
                    $longestOid = strlen($enumeration);
                    $m = $mapperName;
		    
                    if (getenv('DEBUG') == "true") {
	   	                $this->log->log("initial state, ip: ".$hostWithDeviceType['ip'] . " enumeration is " . $enumeration . "... best mapper is: " . $m, Logger::DEBUG);
                    }
                }
                // updated state, found a better match
                if (strlen($enumeration) > $longestOid) {
                    $longestOid = strlen($enumeration);
                    $m = $mapperName;
                    if (getenv('DEBUG') == "true") {
                        $this->log->log("update state, ip: ".$hostWithDeviceType['ip'] . " enumeration is " . $enumeration . "... best mapper is: " . $m, Logger::DEBUG);
                    }
                }

            }
        }

        switch ($m) {
            case "CANOPY":
                $mapper = new CambiumCanopyPMPAccessPointMapper($device);
                break;
            case "CAMBIUMEPMP":
                $mapper = new CambiumEpmpAccessPointMapper($device);
                break;
            case "CAMBIUMPTP650":
                $mapper = new CambiumPTP650Backhaul($device);
                break;
            case "CAMBIUMPTP600":
                $mapper = new CambiumPTP600Backhaul($device);
                break;
            case "CAMBIUMPTP250":
                $mapper = new CambiumPTP250Backhaul($device);
                break;
            case "CAMBIUMPTP500":
                $mapper = new CambiumPTP500Backhaul($device);
                break;
            case "CAMBIUMPTP670":
                $mapper = new CambiumPTP670Backhaul($device);
                break;
            case "CAMBIUMPTP700":
                $mapper = new CambiumPTP700Backhaul($device);
                break;
            case "CAMBIUMPTP800":
                $mapper = new CambiumPTP800Backhaul($device);
                break;
            case "UBNT":
                $identifier = new UbiquitiIdentifier($device);
                $mapper = $identifier->getMapper(); //Ubiquiti doesn't separate their devices well by sysObjectID. This identifier will attempt to determine the right device to return.
                break;
            case "MIMOSABX":
                $mapper = new MimosaBxBackhaul($device);
                break;
            case "MIMOSAAX": //A5-14, A5-18, A5c (FW 2.3+)
                $mapper = new MimosaAxAccessPoint($device);
                break;
            case "ETHERWAN":
                $mapper = new EtherwanSwitch($device);
                break;
            case "MIKROTIK":
                $mapper = new MikroTik($device);
                break;
            case "GENERIC":
            default:
                $mapper = new GenericDeviceMapper($device, $hostWithDeviceType['type'] == 'network_sites');
                break;
        }

        return $mapper;
}

    /**
     * Determine the type of a device and return it to the caller for further processing
     * @param array $chunks
     * @return array
     */
    private function determineDeviceTypes(array $chunks)
    {
        $updatedChunks = [];
        foreach ($chunks as $host)
        {
            //Check to see if we have manually disabled snmp polling on our ICMP only devices
			$templateDetails = $this->templates[$host['template_id']];
            if($templateDetails['snmp_community'] == "disabled" || $host['snmp_overrides']['snmp_community'] == "disabled" ) continue;
			
            $snmpObject = $this->buildSnmpObjectForHost($host);
            try {
                $result = $snmpObject->get("1.3.6.1.2.1.1.2.0");
                $result = explode(":",$result);
                $host['type_query_result'] = ltrim(trim($result[1]),'.');
                array_push($updatedChunks,$host);
            }
            catch (Exception $e)
            {
                if (getenv('DEBUG') == "true")
                {
                    $this->log->log("Failed to get device type from {$host['ip']}, got {$e->getMessage()}",Logger::ERROR);
                }
                continue;
            }
        }

        return $updatedChunks;
    }

    /**
     * Build the SNMP object for a particular host
     * @param array $host
     * @return SNMP
     */
    private function buildSnmpObjectForHost(array $host):SNMP
    {
        $templateDetails = $this->templates[$host['template_id']];
        $snmpVersion = isset($host['snmp_overrides']['snmp_version']) ? $host['snmp_overrides']['snmp_version'] : $templateDetails['snmp_version'];

        switch ($snmpVersion)
        {
            case 2:
                $version = SNMP::VERSION_2C;
                break;
            case 3:
                $version = SNMP::VERSION_3;
                break;
            default:
                $version = SNMP::VERSION_1;
                break;
        }

        $community = isset($host['snmp_overrides']['snmp_community']) ? $host['snmp_overrides']['snmp_community'] : $templateDetails['snmp_community'];

        //Regular GETs (this will bulk GET multiple OIDs)
        $snmp = new SNMP($version, $host['ip'], $community, $this->timeout, $this->retries);
        $snmp->valueretrieval = SNMP_VALUE_LIBRARY;
        $snmp->oid_output_format = SNMP_OID_OUTPUT_NUMERIC;
        $snmp->enum_print = true;
        $snmp->exceptions_enabled = SNMP::ERRNO_ANY;

        if ($version === SNMP::VERSION_3)
        {
            $snmp->setSecurity(
                isset($host['snmp_overrides']['snmp3_sec_level']) ? $host['snmp_overrides']['snmp3_sec_level'] : $templateDetails['snmp3_sec_level'],
                isset($host['snmp_overrides']['snmp3_auth_protocol']) ? $host['snmp_overrides']['snmp3_auth_protocol'] : $templateDetails['snmp3_auth_protocol'],
                isset($host['snmp_overrides']['snmp3_auth_passphrase']) ? $host['snmp_overrides']['snmp3_auth_passphrase'] : $templateDetails['snmp3_auth_passphrase'],
                isset($host['snmp_overrides']['snmp3_priv_protocol']) ? $host['snmp_overrides']['snmp3_priv_protocol'] : $templateDetails['snmp3_priv_protocol'],
                isset($host['snmp_overrides']['snmp3_priv_passphrase']) ? $host['snmp_overrides']['snmp3_priv_passphrase'] : $templateDetails['snmp3_priv_passphrase'],
                isset($host['snmp_overrides']['snmp3_context_name']) ? $host['snmp_overrides']['snmp3_context_name'] : $templateDetails['snmp3_context_name'],
                isset($host['snmp_overrides']['snmp3_context_engine_id']) ? $host['snmp_overrides']['snmp3_context_engine_id'] : $templateDetails['snmp3_context_engine_id']
            );
        }

        return $snmp;
    }
}
