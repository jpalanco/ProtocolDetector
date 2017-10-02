rule http : protocols 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "HTTP Protocol"
  strings: 
    $method = /(GET|POST|PUT|DELETE|PATCH)\s\/.*HTTP\//i
  condition: 
    $method at 0
}
