rule ramnit : protocols
{
  meta:
    author = "Jose Ramon Palanco <jpalanco@gmail.com>"
    description = "ramnit"
  strings:
    $header  = { 00 ff ?? ?? ?? ?? (01|11|13|15|21|23|e2|e8) }

  condition:
    $header at 0 
}

