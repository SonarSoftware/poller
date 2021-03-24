<?php

namespace SonarSoftware\Poller\Models;

use InvalidArgumentException;
use SNMP;

class Device
{
    private $interfaces = [];
    private $id;
    private $metadata = [];
    private $snmpObject;
    private $timer;

    /**
     * @return array
     */
    public function toArray():array
    {
        $structure = [
            'id' => $this->id,
            'metadata' => $this->metadata,
            'timer' => $this->timer,
            'interfaces' => [],
        ];

        foreach ($this->interfaces as $interface)
        {
            array_push($structure['interfaces'],$interface->toArray());
        }

        return $structure;
    }

    /**
     * @param SNMP $snmpObject
     */
    public function setSnmpObject(SNMP $snmpObject)
    {
        $this->snmpObject = $snmpObject;
    }

    /**
     * @return SNMP
     */
    public function getSnmpObject():SNMP
    {
        return $this->snmpObject;
    }

    /**
     * @return array
     */
    public function getInterfaces():array
    {
        return $this->interfaces;
    }

    /**
     * Must be an array of SonarSoftware\Pollers\Models\DeviceInterface objects
     * @param array $interfaces
     */
    public function setInterfaces(array $interfaces)
    {
        $properClass = new DeviceInterface();
        foreach ($interfaces as $interface)
        {
            if (!$interface instanceof $properClass)
            {
                throw new InvalidArgumentException("You must submit an array of SonarSoftware\Pollers\Models\DeviceInterface objects.");
            }
        }
        $this->interfaces = $interfaces;
    }

    /**
     * @param array $metadata
     */
    public function setMetadata(array $metadata)
    {
        $this->metadata = $metadata;
    }

    /**
     * @return array
     */
    public function getMetadata():array
    {
        return $this->metadata;
    }

    /**
     * @param int $id
     */
    public function setId(int $id)
    {
        $this->id = $id;
    }

    /**
     * @return int
     */
    public function getId():int
    {
        return $this->id;
    }
	
	/**
     * @param float $timer in ms
     */
	public function setTimer(float $timer)
    {
        $this->timer = $timer;
    }

    /**
     * @return int timer in ms
     */
    public function getTimer():float
    {
        return $this->timer;
    }
}
