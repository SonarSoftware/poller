<?php

namespace SonarSoftware\Poller\Services;

use Predis\Client;

class TemporaryVariables
{
    /**
     * @param $key
     * @return string
     */
    public static function get($key)
    {
        $client = new Client();
        return $client->get($key);
    }

    /**
     * @param $key
     * @param $value
     * @return mixed
     */
    public static function set($key, $value)
    {
        $client = new Client();
        return $client->set($key, $value);
	}
	/**
     * @param $keyone
     * @param $value
     * @return mixed
     */
	public static function add($keyone, $value)
	{
		$client = new Client();
		return $client->hset($keyone, $value, 1);		
	}
	/**
     * @param $keyone
     * @param $value
     * @return mixed
     */
	public static function remove($keyone, $value)
	{
		$client = new Client();
		return $client->hdel($keyone, $value);		
	}
	/**
     * @param $keyone
     * @return array
     */
	public static function getAll($keyone){
		$client = new Client();
		return $client->hgetall($keyone);		
	}
}