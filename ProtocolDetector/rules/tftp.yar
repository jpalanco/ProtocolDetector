rule tftp : protocols
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "TFTP Protocol"
  strings:
    $read_request = { 00 (01|02) }
    $type_octect = { 6f 63 74 65 74 00 }
    $type_netascii = { 6e 65 74 61 73 63 69 69 00 }

  condition:
    $read_request at 0 and 1 of ($type_*)
}

