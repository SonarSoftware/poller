<?php

namespace SonarSoftware\Poller\Jobs;

use Dotenv\Dotenv;
use Exception;
use GuzzleHttp\Client;
use Monolog\Logger;
use SonarSoftware\Poller\Pollers\IcmpPoller;
use SonarSoftware\Poller\Services\SonarLogger;
use SonarSoftware\Poller\Services\TemporaryVariables;

class PerformIcmpPolling
{
    /**
     * Ping hosts and return to Sonar
     * @throws Exception
     */
    public function perform()
    {
        ini_set('memory_limit','1G');
        set_time_limit(7200);
        $logger = new SonarLogger();

        try {
            $dotenv = new Dotenv(dirname(__FILE__) . "/../../");
            $dotenv->load();

            if (getenv('DEBUG') == "true")
            {
                $logger->log("Starting ICMP polling cycle.",Logger::INFO);
            }

            $startTime = time();

            try {
                $poller = new IcmpPoller();
                $results = $poller->poll($this->args);
            }
            catch (Exception $e)
            {
                $logger->log("Caught an exception when attempting to ping hosts.", Logger::ERROR);
                $logger->log($e->getMessage(), Logger::ERROR);
                return;
            }

            $timeTaken = time() - $startTime;
            if (getenv('DEBUG') == "true")
            {
                $logger->log("Uploading ICMP Results.",Logger::INFO);
            }
            try {
                $client = new Client();
                $client->post(getenv("SONAR_URI") . "/api/poller/icmp", [
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
                    $logger->log("Caught an exception when attempting to deliver ICMP data to Sonar.", Logger::ERROR);
                    $logger->log($e->getMessage(), Logger::ERROR);
                }
                return;
            }

            if (getenv('DEBUG') == "true")
            {
                $logger->log("Finished ICMP polling cycle.",Logger::INFO);
            }
        }
        catch (Exception $e)
        {
            $logger->log("Uncaught ICMP polling exception - {$e->getMessage()}.", Logger::ERROR);
        }
        finally
        {
            TemporaryVariables::set("ICMP Polling Running",null);
        }
    }
}