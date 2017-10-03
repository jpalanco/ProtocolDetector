rule stratum : protocols
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "Stratum Protocol"
  strings:
    $param1 = "id"
    $param2 = "method"
    $param3 = "params"
    $method1 = "mining.subscribe"
    $method2 = "mining.extranonce.subscribe"
    $method3 = "mining.get_transactions"
    $method4 = "mining.submit"

  condition:
    all of ($param*) and 1 of ($method*)
}
