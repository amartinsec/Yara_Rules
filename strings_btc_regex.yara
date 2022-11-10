rule btc_regex
{
  meta:
    description = "Regex for Bitcoin addresses. Used in Clipper/stealer malware"
    author = "amartin@amartinsec.com / @amartinsec"

  strings:
     $btc = "^([13]|bc1)[A-HJ-NP-Za-km-z1-9]{27,34}$" ascii wide nocase //Bitcoin Regex

 
  condition:
    $btc
}
