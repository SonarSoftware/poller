<?php

namespace SonarSoftware\Poller\Jobs;

use Carbon\Carbon;
use Dotenv\Dotenv;
use Exception;
use GuzzleHttp\Client;
use Monolog\Logger;
use SonarSoftware\Poller\Pollers\DeviceMappingPoller;
use SonarSoftware\Poller\Services\SonarLogger;
use SonarSoftware\Poller\Services\TemporaryVariables;

class DetermineDeviceMapping
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


            $deviceMappingFrequency = getenv("DEVICE_MAPPING_FREQUENCY") ? (int)getenv("DEVICE_MAPPING_FREQUENCY") : 15;
            if ($deviceMappingFrequency < 5)
            {
                $deviceMappingFrequency = 5;
            }
            
			
			$currentMinutes = (microtime(true)/60);
			$lastRun = TemporaryVariables::get("Last Device Mapping Run");
			
			if ($currentMinutes - $lastRun < (int)getenv("DEVICE_MAPPING_FREQUENCY") )
			{
				if (getenv('DEBUG') == "true")
				{
					$logger->log("Last device mapping cycle was less than $deviceMappingFrequency minutes ago, aborting.",Logger::INFO);
				}
				return;
			}
			else
			{
				if (getenv('DEBUG') == "true")
				{
					$logger->log("Last device mapping cycle was not less than $deviceMappingFrequency minutes ago, MAPPING for you.",Logger::INFO);	
				}
			}
			
			TemporaryVariables::set("Last Device Mapping Run",$currentMinutes);

            if (getenv('DEBUG') == "true")
            {
                $logger->log("Starting device mapping cycle.",Logger::INFO);
            }

            $startTime = time();

            try {
                $poller = new DeviceMappingPoller();
                $results = $poller->poll($this->args);
            }
            catch (Exception $e)
            {
                $logger->log("Caught an exception when attempting to retrieve device mapping.", Logger::ERROR);
                $logger->log($e->getMessage(), Logger::ERROR);
                return;
            }

            $timeTaken = time() - $startTime;
			if (getenv('DEBUG') == "true")
            {
                $logger->log("Uploading device mapping Results.",Logger::INFO);
            }
            try {
                $client = new Client();
				$logger->log("Uploading device mapping to sonar", Logger::INFO);
                $client->post(getenv("SONAR_URI") . "/api/poller/device_mapping", [
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
                    $logger->log("Caught an exception when attempting to deliver device mapping data to Sonar.", Logger::ERROR);
                    $logger->log($e->getMessage(), Logger::ERROR);
                }
                return;
            }

            if (getenv('DEBUG') == "true")
            {
                $logger->log("Finished device mapping cycle.",Logger::INFO);
            }
        }
        catch (Exception $e)
        {
            $logger->log("Uncaught device mapping exception - {$e->getMessage()}.", Logger::ERROR);
        }
        finally
        {
            TemporaryVariables::set("Device Mapping Running",null);
        }
    }
}