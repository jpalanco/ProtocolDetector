rule ssl : protocols
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "SSL"
  strings:
    $content_type = /(\x13|\x14|\x15|\x16|\x17)/ 
    $version_tsl_1_2 = { 03 03 }
    $version_tsl_1_0 = { 03 01 }
  condition:
    $content_type at 0 and ($version_tsl_1_2 at 1 or $version_tsl_1_0 at 1)
}

