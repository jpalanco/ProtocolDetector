rule dns : protocols
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "DNS Protocol"
  strings:
    $standard_query = { 01 00 00 01 00 00 00 00 00 00 }
  condition:
    $standard_query at 2
}

