<?php

namespace SonarSoftware\Poller\Jobs;

use Dotenv\Dotenv;
use Exception;
use GuzzleHttp\Client;
use Monolog\Logger;
use SonarSoftware\Poller\Pollers\SnmpPoller;
use SonarSoftware\Poller\Services\SonarLogger;
use SonarSoftware\Poller\Services\TemporaryVariables;

class PerformSnmpGets
{
    /**
     * @throws Exception
     */
    public function perform()
    {
        ini_set('memory_limit','2G');
        set_time_limit(7200);

        $logger = new SonarLogger();

        try {
            $dotenv = new Dotenv(dirname(__FILE__) . "/../../");
            $dotenv->load();

            if (getenv('DEBUG') == "true")
            {
                $logger->log("Starting SNMP polling cycle.",Logger::INFO);
            }

            $startTime = time();

            try {
                $poller = new SnmpPoller();
                $results = $poller->poll($this->args);
            }
            catch (Exception $e)
            {
                $logger->log("Caught an exception when attempting to SNMP query hosts.", Logger::ERROR);
                $logger->log($e->getMessage(), Logger::ERROR);
                throw $e;
            }

            $timeTaken = time() - $startTime;
			if (getenv('DEBUG') == "true")
            {
                $logger->log("Uploading SNMP Results.",Logger::INFO);
            }
            try {
                $client = new Client();
                $client->post(getenv("SONAR_URI") . "/api/poller/snmp_gets", [
                    'headers' => [
                        'Content-Type' => 'application/json',
                        'timeout' => 120,
                    ],
                    'json' => [
                        'results' => $results,
                        'api_key' => getenv("API_KEY"),
                        'version' => trim(file_get_contents(dirname(__FILE__) . "/../../resources/version")),
                        'time' => $timeTaken,
                    ]
                ]);
            }
            catch (Exception $e)
            {
                if (getenv('DEBUG') == "true")
                {
                    $logger->log("Caught an exception when attempting to deliver SNMP data to Sonar.", Logger::ERROR);
                    $logger->log($e->getMessage(), Logger::ERROR);
                }
                return;
            }

            if (getenv('DEBUG') == "true")
            {
                $logger->log("Finished SNMP polling cycle.",Logger::INFO);
            }
        }
        catch (Exception $e)
        {
            $logger->log("Uncaught SNMP polling exception - {$e->getMessage()}.", Logger::ERROR);
        }
        finally
        {
            TemporaryVariables::set("SNMP Polling Running",null);
        }
    }
}