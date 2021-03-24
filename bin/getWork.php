<?php

require_once(dirname(__FILE__) . "/../vendor/autoload.php");

use Carbon\Carbon;
use Dotenv\Dotenv;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use League\CLImate\CLImate;
use Monolog\Logger;
use SonarSoftware\Poller\Formatters\Formatter;
use SonarSoftware\Poller\Services\SonarLogger;
use SonarSoftware\Poller\Services\TemporaryVariables;


$climate = new CLImate();
$logger = new SonarLogger();

ini_set('memory_limit','2G');
set_time_limit(60);

try {
    $dotenv = new Dotenv(dirname(__FILE__) . "/../");
    $dotenv->load();
}
catch (Exception $e)
{
    $climate->shout("Could not find .env file at " . dirname(__FILE__) . "/../.env");
    return;
}

Resque::setBackend('localhost:6379');

try {
    $now = Carbon::now("UTC");
    $contents = getWorkFromSonar();
    queueIcmpWork($contents, $now);
    queueSnmpWork($contents, $now);
    queueDeviceMappingWork($contents);
}
catch (Exception $e)
{
    $climate->shout("Failed to get work from Sonar and enqueue it - {$e->getMessage()}");
    if (getenv('DEBUG') == "true")
    {
        $logger->log("Failed to get work from Sonar and enqueue it - {$e->getMessage()}",Logger::ERROR);
    }
}

/**
 * FUNCTIONS
 */


/**
 * Get work from Sonar to be processed
 * @return stdClass
 */
function getWorkFromSonar():stdClass
{
    $client = new Client();
    $logger = new SonarLogger();

    try {
        $result = $client->post(getenv("SONAR_URI") . "/api/poller", [
            'headers' => [
                'Content-Type' => 'application/json',
                'timeout' => 30,
            ],
            'json' => [
                'api_key' => getenv("API_KEY"),
                'version' => trim(file_get_contents(dirname(__FILE__) . "/../resources/version")),
            ]
        ]);
    }
    catch (ClientException $e)
    {
        $response = $e->getResponse();
        try {
            $message = json_decode($response->getBody()->getContents());
            throw new RuntimeException($message->error->message);
        }
        catch (Exception $e)
        {
            throw new RuntimeException($e->getMessage());
        }
    }
    catch (Exception $e)
    {
        throw new RuntimeException($e->getMessage());
    }

    if (getenv('DEBUG') == "true")
    {
        $logger->log("Obtained work from Sonar, queueing..",Logger::INFO);
    }

    return json_decode($result->getBody()->getContents());
}

/**
 * Queue up device mapping work
 * @param stdClass $contents
 */
function queueDeviceMappingWork(stdClass $contents)
{
    $climate = new CLImate();
    $formatter = new Formatter();
	
	$work = $formatter->formatDeviceMappingWork($contents);
	$token = Resque::enqueue('polling', 'SonarSoftware\Poller\Jobs\DetermineDeviceMapping', $work, true);
	$climate->lightGreen("Enqueued device mapping job and got token $token");
}

/**
 * Queue up ICMP work
 * @param stdClass $contents
 * @param Carbon $now
 */
function queueIcmpWork(stdClass $contents, Carbon $now)
{
    $climate = new CLImate();
    $formatter = new Formatter();
    $logger = new SonarLogger();

    $icmpPollingStart = TemporaryVariables::get("ICMP Polling Running");

    $skipIcmpPolling = false;
    if ($icmpPollingStart != null)
    {
        try {
            $icmpPollingStartCarbon = new Carbon($icmpPollingStart, "UTC");
            if ($now->diffInMinutes($icmpPollingStartCarbon) < 30)
            {
                $climate->shout("Skipping ICMP polling, as it is still pending.");
                if (getenv('DEBUG') == "true")
                {
                    $logger->log("Skipping ICMP polling, as it is still pending.",Logger::ERROR);
                }
                $skipIcmpPolling = true;
            }
        }
        catch (Exception $e)
        {
            $logger->log("Could not instantiate Carbon from $icmpPollingStart", Logger::ERROR);
        }
    }
    if ($skipIcmpPolling === false)
    {
        $work = $formatter->formatIcmpHostsFromSonar($contents);
        TemporaryVariables::set("ICMP Polling Running",$now->toDateTimeString());
        $token = Resque::enqueue('polling', 'SonarSoftware\Poller\Jobs\PerformIcmpPolling', $work, true);
        $climate->lightGreen("Enqueued ICMP job and got token $token");
    }
}

/**
 * Queue up SNMP work
 * @param stdClass $contents
 * @param Carbon $now
 */
function queueSnmpWork(stdClass $contents, Carbon $now)
{
    $climate = new CLImate();
    $formatter = new Formatter();
    $logger = new SonarLogger();

    $snmpPollingStart = TemporaryVariables::get("SNMP Polling Running");

    $skipSnmpPolling = false;
    if ($snmpPollingStart != null)
    {
        try {
            $snmpPollingStartCarbon = new Carbon($snmpPollingStart, "UTC");
            if ($now->diffInMinutes($snmpPollingStartCarbon) < 30)
            {
                $climate->shout("Skipping SNMP polling, as it is still pending.");
                if (getenv('DEBUG') == "true")
                {
                    $logger->log("Skipping SNMP polling, as it is still pending.",Logger::ERROR);
                }
                $skipSnmpPolling = true;
            }
        }
        catch (Exception $e)
        {
            $logger->log("Could not instantiate Carbon from $snmpPollingStart", Logger::ERROR);
        }
    }
    if ($skipSnmpPolling === false)
    {
        $work = $formatter->formatSnmpWork($contents);
        TemporaryVariables::set("SNMP Polling Running",$now->toDateTimeString());
        $token = Resque::enqueue('polling', 'SonarSoftware\Poller\Jobs\PerformSnmpGets', $work, true);
        $climate->lightGreen("Enqueued SNMP gets job and got token $token");
    }
}