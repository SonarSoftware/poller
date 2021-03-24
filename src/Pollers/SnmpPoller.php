<?php

namespace SonarSoftware\Poller\Pollers;

use Dotenv\Dotenv;
use Monolog\Logger;
use RuntimeException;
use SNMP;
use SNMPException;
use SonarSoftware\Poller\Formatters\Formatter;
use SonarSoftware\Poller\Services\SonarLogger;

class SnmpPoller
{
    protected $snmpForks;
    protected $timeout;
    protected $log;
    protected $retries;
    protected $templates;
	protected $totalTimeout;

    /** Status constants */
    const GOOD = 2;
    const WARNING = 1;
    const DOWN = 0;

    public function __construct()
    {
        $dotenv = new Dotenv(dirname(__FILE__) . "/../../");
        $dotenv->load();
        $this->snmpForks = (int)getenv("SNMP_FORKS") > 0 ? (int)getenv("SNMP_FORKS") : 25;
        $this->timeout = (int)getenv("SNMP_TIMEOUT") > 0 ? (int)getenv("SNMP_TIMEOUT")*1000000 : 500000;
        $this->retries = (int)getenv("SNMP_RETRIES");
		$this->totalTimeout = (int)getenv("SNMP_POLLING_TIMEOUT") > 0 ? (int)getenv("SNMP_POLLING_TIMEOUT") * 60 : 300;
        $this->log = new SonarLogger();
    }

    /**
     * Collect SNMP data from hosts based on templates
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

                $this->pollDevices($chunks[$i],$fileUniquePrefix, $i);
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
                unlink($file);
            }
            else
            {
                $this->log->log("Couldn't open $file",Logger::INFO);
            }
        }

        $formatter = new Formatter();
        return $formatter->formatSnmpResultsFromSnmpClass($results, $work['hosts']);
    }

    /**
     * Set the status based on the SNMPException parameters
     * @param SNMPException $exception
     * @return array
     */
    private function updateStatusAfterException(SNMPException $exception):array
    {
        $return = [
            'status' => $this::GOOD,
            'status_reason' => trim($exception->getMessage()),
        ];

        switch ($exception->getCode())
        {
            case 8:
            case 16:
            case 32:
            case 64:
                $return['status'] = $this::WARNING;
                break;
            default:
                $return['status'] = $this::DOWN;
                break;
        }

        return $return;
    }

    /**
     * Child polling process
     * @param $chunks
     * @param $fileUniquePrefix
     * @param $counter
     */
    private function pollDevices($chunks, $fileUniquePrefix, $counter)
    {
        $handle = fopen("/tmp/".$fileUniquePrefix . "_sonar_" . $counter,"w");
		$output = false;
        
        if ($handle === false)
        {
            $this->log->log("Failed to open handle for /tmp/$fileUniquePrefix" . "_sonar_$counter",Logger::ERROR);
            throw new RuntimeException("Failed to open handle for /tmp/$fileUniquePrefix" . "_sonar_$counter");
        }

        $resultToWrite = [];
        foreach ($chunks as $host)
        {
            $resultToWrite[$host['ip']] = [
                'results' => [
                    'oids' => null,
                    'interfaces' => null,
                ],
                'status' => [
                    'status' => $this::GOOD,
                    'status_reason' => null,
                ],
                'time' => time(),
				//timer indicates how long(in real time) it took to complete the request for this single device.
				'timer' => 0.0, ///TODO add timer field in the Sonar instance for readability and easy debugging. 
            ];
			$time_start = microtime(true); 
            $templateDetails = $this->templates[$host['template_id']];
            if (count($templateDetails['oids']) === 0 && $templateDetails['collect_interface_statistics'] == false)
            {
                continue;
            }
			//Exit out for ICMP only devices, do not waste resources on them.
            if($templateDetails['snmp_community'] == "disabled" || $host['snmp_overrides']['snmp_community'] == "disabled"){
            	continue;
            }
			
			if (getenv('DEBUG') == "true")
			{
				//this allows a savvy user to be able to determine which threads are failing and can whittle down the hosts causing the problems
				$output = fopen("/tmp/".$fileUniquePrefix . "_HOST_" . $host['ip'] ,"w");
				fclose($output);
			}
			
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

            try {
                if (count($templateDetails['oids']) > 0)
                {
                    $result = $snmp->get(array_values($templateDetails['oids']));
                    $resultToWrite[$host["ip"]]['results']['oids'] = json_decode(json_encode($result),true);
                }
            }
            catch (SNMPException $e)
            {
                $resultToWrite[$host['ip']]['status'] = $this->updateStatusAfterException($e);
            }

            //Interface statistics
            if ($templateDetails['collect_interface_statistics'] == true)
            {
                try {
                    $result = $snmp->walk("1.3.6.1.2.1.2.2.1");
                    $resultToWrite[$host['ip']]['results']['interfaces'] = json_decode(json_encode($result),true);
                }
                catch (SNMPException $e)
                {
                    $resultToWrite[$host['ip']]['status'] = $this->updateStatusAfterException($e);
                }

                try {
                    $result = $snmp->walk("1.3.6.1.2.1.31.1.1.1");
                    $resultToWrite[$host['ip']]['results']['interfaces_64bit'] = json_decode(json_encode($result),true);
                }
                catch (SNMPException $e)
                {
                    //Ignore, the device might not support 64bit counters
                }
            }
            $time_end = microtime(true); 
            $resultToWrite[$host['ip']]['timer'] = $time_end-$time_start;

            if ($resultToWrite[$host['ip']]['timer'] > 20) {
                if (getenv('DEBUG') == "true")
                {
                    $this->log->log("{$host['ip']} took {$resultToWrite[$host['ip']]['timer']} seconds to poll",Logger::WARNING);
                }
            }
			
			//we delete the file, and so only the problem hosts that do not exit their process gracefully are left. 
			if (getenv('DEBUG') == "true")
			{
				unlink("/tmp/".$fileUniquePrefix . "_HOST_" . $host['ip']);
			}
        }
		
        
        fwrite($handle, json_encode($resultToWrite));
        fclose($handle);
    }
}
