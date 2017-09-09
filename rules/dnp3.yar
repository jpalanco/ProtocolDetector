rule dnp3 : protocols 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "DNP3 Protocol"
  strings: 
    $dnp3_header = { 05 64 }
  condition: 
    $dnp3_header at 0 
}

