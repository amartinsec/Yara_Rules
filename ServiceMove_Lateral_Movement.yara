rule servicemove_lateral_movement
{
  meta:
    description = "Yara detection for lateral movement through perception simulation dll hijacking. Lateral movement found by netero1010. See reference for his repo of method."
    author = "amartin@amartinsec.com / @amartinsec"
    reference = "https://github.com/netero1010/ServiceMove-BOF"

  strings:
    $hijackeddll = "C:\\Windows\\System32\\PerceptionSimulation\\hid.dll" fullword ascii
 
  condition:
    $hijackeddll
}
