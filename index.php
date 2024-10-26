<?php

class Address {
    private $workChain;
    private $hash;

    const BOUNCEABLE_TAG = 0x11;
    const NON_BOUNCEABLE_TAG = 0x51;
    const TEST_FLAG = 0x80;

    public function __construct(int $workChain, string $hash) {
        if (strlen($hash) !== 32) {
            throw new Exception('Invalid address hash length: ' . strlen($hash));
        }

        $this->workChain = $workChain;
        $this->hash = $hash;
    }

    public static function isAddress($src): bool {
        return $src instanceof Address;
    }

    public static function isFriendly(string $source): bool {
        return strlen($source) === 48 && preg_match('/[A-Za-z0-9+\/_-]+/', $source);
    }

    public static function isRaw(string $source): bool {
        if (strpos($source, ':') === false) {
            return false;
        }

        [$wc, $hash] = explode(':', $source);

        return is_numeric($wc) && preg_match('/[a-f0-9]{64}/i', $hash);
    }

    public static function normalize($source): string {
        return is_string($source) ? self::parse($source)->toString() : $source->toString();
    }

    public static function parse(string $source): Address {
        if (self::isFriendly($source)) {
            return self::parseFriendly($source)['address'];
        } elseif (self::isRaw($source)) {
            return self::parseRaw($source);
        } else {
            throw new Exception('Unknown address type: ' . $source);
        }
    }

    public static function parseRaw(string $source): Address {
        $parts = explode(":", $source);
        $workChain = (int)$parts[0];
        $hash = hex2bin($parts[1]);

        return new self($workChain, $hash);
    }

    public static function parseFriendly($source): array {
        $addr = is_string($source) ? base64_decode(strtr($source, '-_', '+/')) : $source;
        $parsed = self::parseFriendlyAddress($addr);

        return [
            'isBounceable' => $parsed['isBounceable'],
            'isTestOnly' => $parsed['isTestOnly'],
            'address' => new self($parsed['workchain'], $parsed['hashPart'])
        ];
    }

    private static function parseFriendlyAddress(string $src): array {
        if (strlen($src) !== 36) {
            throw new Exception('Unknown address type: byte length is not equal to 36');
        }

        $addr = substr($src, 0, 34);
        $crc = substr($src, 34, 2);
        $calcedCrc = self::crc16($addr);

        if ($calcedCrc !== $crc) {
            throw new Exception('Invalid checksum: ' . $src);
        }

        $tag = ord($addr[0]);
        $isTestOnly = ($tag & self::TEST_FLAG) !== 0;
        $isBounceable = ($tag === self::BOUNCEABLE_TAG);

        $workchain = (ord($addr[1]) === 0xff) ? -1 : ord($addr[1]);
        $hashPart = substr($addr, 2, 32);

        return compact('isTestOnly', 'isBounceable', 'workchain', 'hashPart');
    }

    private static function crc16_old(string $data): string {
        $crc = 0xFFFF;
        foreach (str_split($data) as $char) {
            $crc ^= ord($char);
            for ($j = 0; $j < 8; $j++) {
                $crc = ($crc & 1) ? ($crc >> 1) ^ 0xA001 : $crc >> 1;
            }
        }
        return pack('v', $crc);
    }
    
    private static function crc16(string $data): string {
	    $poly = 0x1021;
	    $reg = 0;
	    $message = $data . "\0\0"; // Append two null bytes to the data
	
	    for ($i = 0; $i < strlen($message); $i++) {
	        $byte = ord($message[$i]);
	        $mask = 0x80;
	
	        while ($mask > 0) {
	            $reg <<= 1;
	
	            if ($byte & $mask) {
	                $reg += 1;
	            }
	            $mask >>= 1;
	
	            if ($reg > 0xffff) {
	                $reg &= 0xffff;
	                $reg ^= $poly;
	            }
	        }
	    }
	
	    // Convert the final CRC to a 2-byte binary string
	    return chr($reg >> 8) . chr($reg & 0xff);
	}

    public function toRawString(): string {
        return $this->workChain . ':' . bin2hex($this->hash);
    }

    public function equals(Address $src): bool {
        return $src->workChain === $this->workChain && $src->hash === $this->hash;
    }

    public function toStringBuffer(array $args = []): string {
        $testOnly = $args['testOnly'] ?? false;
        $bounceable = $args['bounceable'] ?? true;

        $tag = $bounceable ? self::BOUNCEABLE_TAG : self::NON_BOUNCEABLE_TAG;
        if ($testOnly) {
            $tag |= self::TEST_FLAG;
        }

        $addr = pack('C', $tag) . pack('C', $this->workChain) . $this->hash;
        $addrWithCrc = $addr . self::crc16($addr);

        return $addrWithCrc;
    }

    public function toString(array $args = []): string {
        $urlSafe = $args['urlSafe'] ?? true;
        $buffer = $this->toStringBuffer($args);
        $encoded = base64_encode($buffer);

        return $urlSafe ? strtr($encoded, '+/', '-_') : $encoded;
    }
}

$address = Address::parseRaw("0:2cf55953e92efbeadab7ba725c3f93a0b23f842cbba72d7b8e6f510a70e422e3");
echo $address->toString(['testOnly'=>true]) . "\n";
echo $address->toString(['testOnly'=>false, 'bounceable'=> true, 'urlSafe'=> false]);
